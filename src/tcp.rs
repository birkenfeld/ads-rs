//! Contains the TCP client to connect to an ADS server.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

use byteorder::{LE, ByteOrder, ReadBytesExt, WriteBytesExt};
use crossbeam_channel::{bounded, unbounded, Sender, Receiver};

use crate::errors::ads_error;
use crate::notify;
use crate::{AmsAddr, AmsNetId, Error, Result};

/// An ADS protocol command.
// https://infosys.beckhoff.com/content/1033/tc3_ads_intro/115847307.html?id=7738940192708835096
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum Command {
    /// Return device info
    DevInfo = 1,
    /// Read some data
    Read = 2,
    /// Write some data
    Write = 3,
    /// Write some data, then read back some data
    /// (used as a poor-man's function call)
    ReadWrite = 9,
    /// Read the ADS and device state
    ReadState = 4,
    /// Set the ADS and device state
    WriteControl = 5,
    /// Add a notification for a given index
    AddNotification = 6,
    /// Add a notification for a given index
    DeleteNotification = 7,
    /// Change occurred in a given notification,
    /// can be sent by the PLC only
    Notification = 8,
}

/// Size of the AMS/TCP + ADS headers
// https://infosys.beckhoff.com/content/1033/tc3_ads_intro/115845259.html?id=6032227753916597086
const HEADER_SIZE: usize = 38;
const AMS_HEADER_SIZE: usize = HEADER_SIZE - 6;  // without leading nulls and length
const DEFAULT_BUFFER_SIZE: usize = 100;

#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    connect: Option<Duration>,
    read: Option<Duration>,
    write: Option<Duration>,
}

impl Timeouts {
    pub fn new(duration: Duration) -> Self {
        Self { connect: Some(duration), read: Some(duration), write: Some(duration) }
    }

    pub fn none() -> Self {
        Self { connect: None, read: None, write: None }
    }
}

/// Represents a connection to a ADS server.
pub struct Client {
    invoke_id: Cell<u32>,
    socket: TcpStream,
    read_timeout: Option<Duration>,
    source: AmsAddr,
    buf_send: Sender<Vec<u8>>,
    reply_recv: Receiver<Vec<u8>>,
    notif_recv: Receiver<notify::Notification>,
    /// active notification handles
    notif_handles: RefCell<BTreeSet<(AmsAddr, notify::Handle)>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        // Close all open notification handles.
        for &(addr, handle) in &*self.notif_handles.borrow() {
            let _ = self.device(addr).delete_notification(handle);
        }

        // Need to shutdown the connection since the socket is duplicated in the
        // reader thread.  This will cause the read() in the thread to return
        // with no data.
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

impl Client {
    /// Open a new connection to an ADS server.
    ///
    /// If connecting to a server that has an AMS router, it needs to have a
    /// route set for the source IP and NetID, otherwise the connection will be
    /// closed immediately.  The route can be added from TwinCAT, or this
    /// crate's `udp::add_route` helper can be used to add a route via UDP
    /// message.
    ///
    /// `source` is the AMS address to to use as the source; the NetID needs to
    /// match the route entry in the server.  If None, the NetID is constructed
    /// from the local IP address with .1.1 appended; if there is no IPv4
    /// address, `127.0.0.1.1.1` is used.
    ///
    /// The AMS port of `source` is not important, as long as it is not a
    /// well-known service port; an ephemeral port number > 49152 is
    /// recommended.  If None, the port is set to 58913.
    ///
    /// Since all communications is supposed to be handled by an ADS router,
    /// only one TCP/ADS connection can exist between two hosts. Non-TwinCAT
    /// clients should make sure to replicate this behavior, as opening a second
    /// connection will close the first.
    pub fn new(addr: impl ToSocketAddrs, timeouts: Timeouts, source: Option<AmsAddr>) -> Result<Self> {
        let addr = addr.to_socket_addrs()?.next().unwrap();
        let socket = if let Some(timeout) = timeouts.connect {
            TcpStream::connect_timeout(&addr, timeout)?
        } else {
            TcpStream::connect(&addr)?
        };
        socket.set_nodelay(true)?;
        socket.set_write_timeout(timeouts.write)?;
        let source = match source {
            Some(id) => id,
            None => {
                let my_addr = socket.local_addr()?.ip();
                if let IpAddr::V4(ip) = my_addr {
                    let [a, b, c, d] = ip.octets();
                    // use some random ephemeral port
                    AmsAddr::new(AmsNetId::new(a, b, c, d, 1, 1), 58913)
                } else {
                    AmsAddr::new(AmsNetId::new(127, 0, 0, 1, 1, 1), 58913)
                }
            }
        };
        let socket_clone = socket.try_clone()?;
        let (buf_send, buf_recv) = bounded(10);
        let (reply_send, reply_recv) = bounded(1);
        let (notif_send, notif_recv) = unbounded();
        let mut source_bytes = [0; 8];
        source.write_to(&mut &mut source_bytes[..]).unwrap();
        let reader = Reader {
            socket: socket_clone,
            source: source_bytes,
            buf_recv,
            reply_send,
            notif_send,
        };
        std::thread::spawn(|| reader.run());
        Ok(Client {
            socket,
            source,
            buf_send,
            reply_recv,
            notif_recv,
            invoke_id: Cell::new(0),
            read_timeout: timeouts.read,
            notif_handles: Default::default(),
        })
    }

    /// Get a receiver for notifications.
    pub fn get_notification_channel(&self) -> Receiver<notify::Notification> {
        self.notif_recv.clone()
    }

    /// Return a wrapper that executes operations for a target device (known by
    /// Net-ID and port).
    pub fn device(&self, addr: AmsAddr) -> Device<'_> {
        Device { client: self, addr }
    }

    /// Low-level function to execute an ADS command.
    ///
    /// Writes a data from a number of input buffers, and returns data in
    /// a number of output buffers.
    pub fn communicate(&self,
                       cmd: Command,
                       target: AmsAddr,
                       data_in: &[&[u8]],
                       data_out: &mut [&mut [u8]]) -> Result<usize> {
        self.invoke_id.set(self.invoke_id.get().wrapping_add(1));
        let data_in_len = data_in.iter().map(|v| v.len()).sum::<usize>();
        let mut request = Vec::with_capacity(HEADER_SIZE + data_in_len);

        // Fill the outgoing header.
        // first two bytes are always 0
        let rest_len = (AMS_HEADER_SIZE + data_in_len).try_into()?;
        request.write_u16::<LE>(0)?;                   // initial padding
        request.write_u32::<LE>(rest_len)?;            // length of rest of message
        target.write_to(&mut request)?;                // dest netid+port
        self.source.write_to(&mut request)?;           // source netid+port
        request.write_u16::<LE>(cmd as u16)?;          // command id
        request.write_u16::<LE>(4)?;                   // state flags (4 = send command)
        request.write_u32::<LE>(data_in_len as u32)?;  // length (overflow checked above)
        request.write_u32::<LE>(0)?;                   // error, always 0 when sending
        request.write_u32::<LE>(self.invoke_id.get())?;      // invoke ID

        // Write the outgoing header and user data.
        for buf in data_in {
            request.extend_from_slice(buf);
        }
        (&self.socket).write_all(&request)?;

        // Get a reply from the reader thread, with timeout or not.
        let reply = if let Some(tmo) = self.read_timeout {
            self.reply_recv.recv_timeout(tmo).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout")
            })?
        } else {
            self.reply_recv.recv().unwrap()
        };

        // Validate the incoming reply.  The reader thread already made sure that
        // it is consistent and addressed to us.

        // Get the pure data length, without result field.
        let data_len = LE::read_u32(&reply[2..6]) as usize - AMS_HEADER_SIZE + 4;

        // The source netid/port must match what we sent.
        if reply[14..22] != request[6..14] {
            return Err(Error::Communication("unexpected originating address", 0));
        }
        // Read the other fields we need.
        let mut ptr = &reply[22..];
        let ret_cmd = ptr.read_u16::<LE>()?;
        let state_flags = ptr.read_u16::<LE>()?;
        let _len = ptr.read_u32::<LE>()?;  // includes result field
        let error_code = ptr.read_u32::<LE>()?;
        let invoke_id = ptr.read_u32::<LE>()?;
        let result = ptr.read_u32::<LE>()?;

        // Command must match.
        if ret_cmd != cmd as u16 {
            return Err(Error::Communication("unexpected command", ret_cmd as u32));
        }
        // State flags must be "4 | 1".
        if state_flags != 5 {
            return Err(Error::Communication("unexpected state flags", state_flags as u32));
        }
        // Invoke ID must match what we sent.
        if invoke_id != self.invoke_id.get() {
            return Err(Error::Communication("unexpected invoke ID", invoke_id));
        }
        // Check error code in AMS header.
        if error_code != 0 {
            return ads_error(error_code);
        }
        // Check result field in payload, only relevant if error_code == 0.
        if result != 0 {
            return ads_error(result);
        }

        // Distribute the data into the user output buffers.
        let mut offset = HEADER_SIZE + 4;
        let mut rest_len = data_len;
        for buf in data_out {
            let n = buf.len().min(rest_len);
            buf.copy_from_slice(&reply[offset..offset + n]);
            offset += n;
            rest_len -= n;
            if rest_len == 0 {
                break;
            }
        }

        // Send back the Vec buffer to the reader thread.
        self.buf_send.send(reply).unwrap();

        // Return either the error or the length of data.
        Ok(data_len)
    }
}

// Implementation detail: reader thread that takes replies and notifications
// and distributes them accordingly.
struct Reader {
    socket: TcpStream,
    source: [u8; 8],
    buf_recv: Receiver<Vec<u8>>,
    reply_send: Sender<Vec<u8>>,
    notif_send: Sender<notify::Notification>,
}

impl Reader {
    fn run(mut self) {
        if self.run_inner().is_err() {
            // We can't do much here.  But try to shut down the socket so that
            // the main client can't be used anymore either.
            let _ = self.socket.shutdown(Shutdown::Both);
        }
    }

    fn run_inner(&mut self) -> Result<()> {
        // Deactivate any read timeout that the user may have set.
        self.socket.set_read_timeout(None)?;

        loop {
            // Get a buffer from the free-channel or create a new one.
            let mut buf = self.buf_recv.try_recv()
                                       .unwrap_or_else(|_| Vec::with_capacity(DEFAULT_BUFFER_SIZE));
            buf.resize(HEADER_SIZE, 0);

            // Read a header from the socket.
            self.socket.read_exact(&mut buf)?;

            // If the header isn't self-consistent, abort the connection.
            let packet_length = LE::read_u32(&buf[2..6]) as usize;
            let rest_length = LE::read_u32(&buf[26..30]) as usize;

            // First two bytes must be zero, and the two length fields must agree.
            if buf[..2] != [0, 0] || rest_length != packet_length - AMS_HEADER_SIZE {
                self.socket.shutdown(Shutdown::Both)?;
                return Ok(());
            }

            // Read the rest of the message.
            buf.resize(HEADER_SIZE + rest_length, 0);
            self.socket.read_exact(&mut buf[HEADER_SIZE..])?;

            // Check that the packet is meant for us.
            if buf[6..14] != self.source {
                continue;
            }

            // If it looks like a reply, send it back to the requesting thread,
            // it will handle further validation.
            if LE::read_u16(&buf[22..24]) != Command::Notification as u16 {
                self.reply_send.send(buf).unwrap();
                continue;
            }

            // Validate notification message fields.
            let state_flags = LE::read_u16(&buf[24..26]);
            let error_code = LE::read_u32(&buf[30..34]);
            let length = LE::read_u32(&buf[38..42]) as usize;
            if state_flags != 4 || error_code != 0 || length != rest_length - 4 || length < 4 {
                continue;
            }

            // Send the notification to whoever wants to receive it.
            if let Ok(notif) = notify::Notification::new(buf) {
                self.notif_send.send(notif).unwrap();
            }
        }
    }
}


/// A `Client` wrapper that talks to a specific ADS device.
#[derive(Clone, Copy)]
pub struct Device<'c> {
    client: &'c Client,
    addr: AmsAddr,
}

impl<'c> Device<'c> {
    /// Read the device's name + version.
    pub fn get_info(&self) -> Result<DeviceInfo> {
        let mut data = [0; 20];
        self.client.communicate(Command::DevInfo, self.addr, &[], &mut [&mut data])?;
        let name = data[4..].iter().take_while(|&&ch| ch > 0)
                                   .map(|&ch| ch as char).collect::<String>();
        Ok(DeviceInfo {
            major: data[0],
            minor: data[1],
            version: LE::read_u16(&data[2..]),
            name
        })
    }

    /// Read some data at a given index group/offset.
    pub fn read(&self, index_group: u32, index_offset: u32, data: &mut [u8]) -> Result<usize> {
        let mut header = [0; 12];
        LE::write_u32_into(&[index_group, index_offset, data.len().try_into()?], &mut header);
        let mut len = [0; 4];
        self.client.communicate(Command::Read, self.addr, &[&header], &mut [&mut len, data])?;
        Ok(u32::from_le_bytes(len) as usize)
    }

    /// Read some data at a given index group/offset.
    pub fn read_exact(&self, index_group: u32, index_offset: u32, data: &mut [u8]) -> Result<()> {
        if self.read(index_group, index_offset, data)? != data.len() {
            return Err(Error::Communication("returned less data than expected", data.len() as u32));
        }
        Ok(())
    }

    /// Write some data to a given index group/offset.
    pub fn write(&self, index_group: u32, index_offset: u32, data: &[u8]) -> Result<()> {
        let mut header = [0; 12];
        LE::write_u32_into(&[index_group, index_offset, data.len().try_into()?], &mut header);
        self.client.communicate(Command::Write, self.addr, &[&header, data], &mut [])?;
        Ok(())
    }

    /// Write some data to a given index group/offset and then read back some
    /// reply from there.  This is not the same as a write() followed by read();
    /// it is used as a kind of RPC call.
    pub fn write_read(&self, index_group: u32, index_offset: u32, write_data: &[u8],
                      read_data: &mut [u8]) -> Result<usize> {
        let mut header = [0; 16];
        LE::write_u32_into(&[index_group, index_offset,
                             read_data.len().try_into()?, write_data.len().try_into()?], &mut header);
        let mut len = [0; 4];
        self.client.communicate(Command::ReadWrite, self.addr,
                                &[&header, write_data], &mut [&mut len, read_data])?;
        Ok(u32::from_le_bytes(len) as usize)
    }

    /// Return the ADS and device state of the device.
    pub fn get_state(&self) -> Result<(AdsState, u16)> {
        let mut data = [0; 4];
        self.client.communicate(Command::ReadState, self.addr, &[], &mut [&mut data])?;
        Ok((AdsState::try_from(LE::read_u16(&data))?, LE::read_u16(&data[2..])))
    }

    /// (Try to) set the ADS and device state of the device.
    pub fn write_control(&self, ads_state: AdsState, dev_state: u16) -> Result<()> {
        let mut data = [0; 8];
        LE::write_u16_into(&[ads_state as u16, dev_state], &mut data[..4]);
        self.client.communicate(Command::WriteControl, self.addr, &[&data], &mut [])?;
        Ok(())
    }

    /// Add a notification handle for some index group/offset.
    ///
    /// Notifications are delivered via a MPMC channel whose reading end can be
    /// obtained from `get_notification_channel` on the `Client` object.
    ///
    /// If the notification is not deleted explictly using
    /// `delete_notification`, it is deleted when the `Client` object is
    /// dropped.
    pub fn add_notification(&self, index_group: u32, index_offset: u32,
                            attributes: notify::Attributes) -> Result<notify::Handle> {
        let mut data = [0; 40];
        LE::write_u32_into(&[index_group,
                             index_offset,
                             attributes.length.try_into()?,
                             attributes.trans_mode as u32,
                             attributes.max_delay.as_millis().try_into()?,
                             attributes.cycle_time.as_millis().try_into()?],
                           // final 16 bytes are reserved
                           &mut data[0..24]);
        let mut handle = [0; 4];
        self.client.communicate(Command::AddNotification, self.addr,
                                &[&data], &mut [&mut handle])?;
        let handle = u32::from_le_bytes(handle);
        self.client.notif_handles.borrow_mut().insert((self.addr, handle));
        Ok(handle)
    }

    /// Delete a notification with given handle.
    pub fn delete_notification(&self, handle: notify::Handle) -> Result<()> {
        let data = handle.to_le_bytes();
        self.client.communicate(Command::DeleteNotification, self.addr, &[&data], &mut [])?;
        self.client.notif_handles.borrow_mut().remove(&(self.addr, handle));
        Ok(())
    }
}

/// Device info returned from an ADS server.
#[derive(Debug)]
pub struct DeviceInfo {
    pub name: String,
    pub major: u8,
    pub minor: u8,
    pub version: u16,
}

/// The ADS state of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AdsState {
    Invalid   = 0,
    Idle      = 1,
    Reset     = 2,
    Init      = 3,
    Start     = 4,
    Run       = 5,
    Stop      = 6,
    SaveCfg   = 7,
    LoadCfg   = 8,
    PowerFail = 9,
    PowerGood = 10,
    Error     = 11,
    Shutdown  = 12,
    Suspend   = 13,
    Resume    = 14,
    Config    = 15,
    Reconfig  = 16,
}

impl TryFrom<u16> for AdsState {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        Ok(match value {
            0  => Self::Invalid,
            1  => Self::Idle,
            2  => Self::Reset,
            3  => Self::Init,
            4  => Self::Start,
            5  => Self::Run,
            6  => Self::Stop,
            7  => Self::SaveCfg,
            8  => Self::LoadCfg,
            9  => Self::PowerFail,
            10 => Self::PowerGood,
            11 => Self::Error,
            12 => Self::Shutdown,
            13 => Self::Suspend,
            14 => Self::Resume,
            15 => Self::Config,
            16 => Self::Reconfig,
            _  => return Err(Error::Communication("invalid ADS state", value as u32))
        })
    }
}

impl FromStr for AdsState {
    type Err = &'static str;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match &*s.to_ascii_lowercase() {
            "invalid" => Self::Invalid,
            "idle" => Self::Idle,
            "reset" => Self::Reset,
            "init" => Self::Init,
            "start" => Self::Start,
            "run" => Self::Run,
            "stop" => Self::Stop,
            "savecfg" => Self::SaveCfg,
            "loadcfg" => Self::LoadCfg,
            "powerfail" => Self::PowerFail,
            "powergood" => Self::PowerGood,
            "error" => Self::Error,
            "shutdown" => Self::Shutdown,
            "suspend" => Self::Suspend,
            "resume" => Self::Resume,
            "config" => Self::Config,
            "reconfig" => Self::Reconfig,
            _  => return Err("invalid state name")
        })
    }
}
