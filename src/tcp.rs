//! Contains the TCP client to connect to an ADS server.

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
const REPLY_HEADER_SIZE: usize = HEADER_SIZE + 4;  // with result field
const DEFAULT_BUFFER_SIZE: usize = 100;

/// Represents a connection to a ADS server.
pub struct Client {
    invoke_id: u32,
    socket: TcpStream,
    read_timeout: Option<Duration>,
    channels: Option<Channels>,
    source: AmsAddr,
    write_buf: Vec<u8>,
}

/// Implementation detail: once a notification is created, we switch to reading replies
/// from a separate thread and send around buffers via channels.
struct Channels {
    buf_send: Sender<Vec<u8>>,
    reply_recv: Receiver<Vec<u8>>,
    notif_recv: Receiver<notify::Notification>,
}

impl Drop for Client {
    fn drop(&mut self) {
        // Need to shutdown the connection since the socket may still be
        // duplicated in the reader thread.  This will cause the read() in the
        // thread to return with no data.
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

impl Client {
    /// Open a new connection to an ADS server.
    pub fn new(addr: impl ToSocketAddrs,
               connect_timeout: Option<Duration>,
               source: Option<AmsAddr>) -> Result<Self> {
        let addr = addr.to_socket_addrs()?.next().unwrap();
        let socket = if let Some(timeout) = connect_timeout {
            TcpStream::connect_timeout(&addr, timeout)?
        } else {
            TcpStream::connect(&addr)?
        };
        socket.set_nodelay(true)?;
        let source = match source {
            Some(id) => id,
            None => {
                let my_addr = socket.local_addr()?.ip();
                if let IpAddr::V4(ip) = my_addr {
                    let [a, b, c, d] = ip.octets();
                    AmsAddr::new(AmsNetId::new(a, b, c, d, 1, 1), 0)
                } else {
                    AmsAddr::new(AmsNetId::new(127, 0, 0, 1, 1, 1), 0)
                }
            }
        };
        Ok(Client {
            invoke_id: 0,
            channels: None,
            read_timeout: None,
            write_buf: Vec::with_capacity(1024),
            socket,
            source,
        })
    }

    /// Get a receiver for notifications.
    pub fn get_notification_channel(&mut self) -> Receiver<notify::Notification> {
        if self.channels.is_none() {
            self.start_async();
        }
        self.channels.as_ref().unwrap().notif_recv.clone()
    }

    // Start a separate thread to handle notifications and replies on the same socket.
    fn start_async(&mut self) {
        assert!(self.channels.is_none());
        let socket = self.socket.try_clone().expect("cloning socket");
        let (buf_send, buf_recv) = bounded(10);
        let (reply_send, reply_recv) = bounded(1);
        let (notif_send, notif_recv) = unbounded();
        let reader = Reader {
            socket,
            buf_recv,
            reply_send,
            notif_send,
        };
        self.channels = Some(Channels {
            buf_send,
            reply_recv,
            notif_recv,
        });
        std::thread::spawn(|| reader.run());
    }

    /// Set the read and write timeout for socket read and write operations.
    pub fn set_timeouts(&mut self, read_timeout: Option<Duration>,
                       write_timeout: Option<Duration>) -> Result<()> {
        self.read_timeout = read_timeout;
        self.socket.set_read_timeout(read_timeout)?;
        self.socket.set_write_timeout(write_timeout)?;
        Ok(())
    }

    /// Return a wrapper that executes operations for a target device (known by
    /// Net-ID and port).
    pub fn device(self, addr: AmsAddr) -> Device {
        Device { client: self, addr }
    }

    /// Low-level function to execute an ADS command.
    ///
    /// Writes a data from a number of input buffers, and returns data in
    /// a number of output buffers.
    pub fn communicate(&mut self,
                       cmd: Command,
                       target: AmsAddr,
                       data_in: &[&[u8]],
                       data_out: &mut [&mut [u8]]) -> Result<usize> {
        self.invoke_id = self.invoke_id.wrapping_add(1);
        let data_in_len = data_in.iter().map(|v| v.len()).sum::<usize>();
        let data_out_len = data_out.iter().map(|v| v.len()).sum::<usize>();
        let mut header_in = [0; HEADER_SIZE];
        let mut header_out = [0; REPLY_HEADER_SIZE];

        // Fill the outgoing header.
        // first two bytes are always 0
        let mut ptr = &mut header_in[2..];
        let rest_len = (HEADER_SIZE + data_in_len - 6).try_into()?;
        ptr.write_u32::<LE>(rest_len)?;            // length of rest of message
        target.write_to(&mut ptr)?;                // dest netid+port
        self.source.write_to(&mut ptr)?;           // source netid+port
        ptr.write_u16::<LE>(cmd as u16)?;          // command id
        ptr.write_u16::<LE>(4)?;                   // state flags (4 = send command)
        ptr.write_u32::<LE>(data_in_len as u32)?;  // length (overflow checked above)
        ptr.write_u32::<LE>(0)?;                   // error, always 0 when sending
        ptr.write_u32::<LE>(self.invoke_id)?;      // invoke ID

        // Write the outgoing header and user data.
        self.write_buf.clear();
        self.write_buf.extend_from_slice(&header_in);
        for buf in data_in {
            self.write_buf.extend_from_slice(buf);
        }
        self.socket.write_all(&self.write_buf)?;

        // Validation of the incoming reply.
        let validate_reply = |header_out: &[u8]| {
            // target netid/port must match what we sent
            if header_out[6..14] != header_in[14..22] {
                return Err(Error::Communication("unexpected return address", 0));
            }
            // validate other fields
            let mut ptr = &header_out[24..];
            let state_flags = ptr.read_u16::<LE>()?;
            let data_len = ptr.read_u32::<LE>()? as usize;
            let error_code = ptr.read_u32::<LE>()?;
            let invoke_id = ptr.read_u32::<LE>()?;
            let result = ptr.read_u32::<LE>()?;

            // state flags must be "4 | 1"
            if state_flags != 5 {
                return Err(Error::Communication("unexpected state flags", state_flags as u32));
            }
            // length of return data
            if data_len > data_out_len + 4 {
                return Err(Error::Communication("excessive reply data length", data_len as u32));
            }
            // error code (can be in two positions)
            if error_code != 0 {
                return ads_error(error_code);
            }
            // invoke ID must match what we sent
            if invoke_id != self.invoke_id {
                return Err(Error::Communication("unexpected invoke ID", invoke_id));
            }
            // error code (result field)
            if result != 0 {
                return ads_error(result);
            }

            Ok(data_len - 4)
        };

        if let Some(channels) = &self.channels {
            // Get a reply from the reader thread, with timeout or not.
            let reply = if let Some(tmo) = self.read_timeout {
                channels.reply_recv.recv_timeout(tmo).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout")
                })?
            } else {
                channels.reply_recv.recv().unwrap()
            };
            let data_len = validate_reply(&reply)?;
            let mut rest_len = data_len;

            // Distribute the data into the user output buffers.
            let mut offset = REPLY_HEADER_SIZE;
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
            channels.buf_send.send(reply).unwrap();
            Ok(data_len)
        } else {
            // Read and check the incoming header.
            self.socket.read_exact(&mut header_out)?;
            let data_len = validate_reply(&header_out)?;
            let mut rest_len = data_len;

            // Read the incoming user data.
            for buf in data_out {
                let n = buf.len().min(rest_len);
                self.socket.read_exact(&mut buf[..n])?;
                rest_len -= n;
                if rest_len == 0 {
                    break;
                }
            }
            Ok(data_len)
        }
    }
}

/// Implementation detail: reader thread that takes replies and notifications
/// and distributes them accordingly.
struct Reader {
    socket: TcpStream,
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

            // Read a message from the socket.
            self.socket.read_exact(&mut buf)?;
            let rest_length = LE::read_u32(&buf[26..30]) as usize;
            buf.resize(HEADER_SIZE + rest_length, 0);
            self.socket.read_exact(&mut buf[HEADER_SIZE..])?;

            // Check if it's a reply or a notification.
            if LE::read_u16(&buf[16..18]) == Command::Notification as u16 {
                // Read the rest of the message.
                self.notif_send.send(notify::Notification::new(buf)).unwrap();
            } else {
                // Read the rest of the message.
                self.reply_send.send(buf).unwrap();
            }
        }
    }
}


/// A `Client` that talks to a specific ADS device.
pub struct Device {
    client: Client,
    addr: AmsAddr,
}

impl Device {
    /// Return back the `Client` of the device.
    pub fn into_inner(self) -> Client {
        self.client
    }

    /// Read the devices' name + version.
    pub fn get_info(&mut self) -> Result<DeviceInfo> {
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
    pub fn read(&mut self, index_group: u32, index_offset: u32, data: &mut [u8]) -> Result<usize> {
        let mut header = [0; 12];
        LE::write_u32_into(&[index_group, index_offset, data.len().try_into()?], &mut header);
        let mut len = [0; 4];
        self.client.communicate(Command::Read, self.addr, &[&header], &mut [&mut len, data])
    }

    /// Read some data at a given index group/offset.
    pub fn read_exact(&mut self, index_group: u32, index_offset: u32, data: &mut [u8]) -> Result<()> {
        if self.read(index_group, index_offset, data)? != data.len() {
            return Err(Error::Communication("returned less data than expected", data.len() as u32));
        }
        Ok(())
    }

    /// Write some data to a given index group/offset.
    pub fn write(&mut self, index_group: u32, index_offset: u32, data: &[u8]) -> Result<()> {
        let mut header = [0; 12];
        LE::write_u32_into(&[index_group, index_offset, data.len().try_into()?], &mut header);
        self.client.communicate(Command::Write, self.addr, &[&header, data], &mut [])?;
        Ok(())
    }

    /// Write some data to a given index group/offset and then read back some reply from there.
    /// This is not the same as a write() followed by read(); it is used as a kind of RPC call.
    pub fn write_read(&mut self, index_group: u32, index_offset: u32, write_data: &[u8],
                      read_data: &mut [u8]) -> Result<usize> {
        let mut header = [0; 16];
        LE::write_u32_into(&[index_group, index_offset,
                             read_data.len().try_into()?, write_data.len().try_into()?], &mut header);
        let mut len = [0; 4];
        self.client.communicate(Command::Read, self.addr,
                                &[&header, write_data], &mut [&mut len, read_data])
    }

    /// Return the ADS and device state of the device.
    pub fn get_state(&mut self) -> Result<(AdsState, u16)> {
        let mut data = [0; 4];
        self.client.communicate(Command::ReadState, self.addr, &[], &mut [&mut data])?;
        Ok((AdsState::try_from(LE::read_u16(&data))?, LE::read_u16(&data[2..])))
    }

    /// (Try to) set the ADS and device state of the device.
    pub fn write_control(&mut self, ads_state: AdsState, dev_state: u16) -> Result<()> {
        let mut data = [0; 8];
        LE::write_u16_into(&[ads_state as u16, dev_state], &mut data[..4]);
        self.client.communicate(Command::Write, self.addr, &[&data], &mut [])?;
        Ok(())
    }

    /// Add a notification handle for some index group/offset.
    pub fn add_notification(&mut self, index_group: u32, index_offset: u32,
                            attributes: notify::Attributes) -> Result<notify::Handle> {
        // Need to go to async mode before a notification can arrive
        self.client.start_async();

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
        Ok(u32::from_le_bytes(handle))
    }

    /// Delete a notification with given handle.
    pub fn delete_notification(&mut self, handle: notify::Handle) -> Result<()> {
        let data = handle.to_le_bytes();
        self.client.communicate(Command::DeleteNotification, self.addr, &[&data], &mut [])?;
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
