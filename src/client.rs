//! Contains the TCP client to connect to an ADS server.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

use byteorder::{ByteOrder, ReadBytesExt, LE};
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};

use crate::errors::{ads_error, ErrContext};
use crate::notif;
use crate::{AmsAddr, AmsNetId, Error, Result};

use zerocopy::byteorder::{U16, U32};
use zerocopy::{AsBytes, FromBytes};

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

impl Command {
    fn action(self) -> &'static str {
        match self {
            Command::DevInfo => "get device info",
            Command::Read => "read data",
            Command::Write => "write data",
            Command::ReadWrite => "write and read data",
            Command::ReadState => "read state",
            Command::WriteControl => "write control",
            Command::AddNotification => "add notification",
            Command::DeleteNotification => "delete notification",
            Command::Notification => "notification",
        }
    }
}

/// Size of the AMS/TCP + ADS headers
// https://infosys.beckhoff.com/content/1033/tc3_ads_intro/115845259.html?id=6032227753916597086
const HEADER_SIZE: usize = 38;
const AMS_HEADER_SIZE: usize = HEADER_SIZE - 6; // without leading nulls and length
const DEFAULT_BUFFER_SIZE: usize = 100;

/// Holds the different timeouts that will be used by the Client.
/// None means no timeout in every case.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// Connect timeout
    pub connect: Option<Duration>,
    /// Reply read timeout
    pub read: Option<Duration>,
    /// Socket write timoeut
    pub write: Option<Duration>,
}

impl Timeouts {
    /// Create a new `Timeouts` where all values are identical.
    pub fn new(duration: Duration) -> Self {
        Self { connect: Some(duration), read: Some(duration), write: Some(duration) }
    }

    /// Create a new `Timeouts` without any timeouts specified.
    pub fn none() -> Self {
        Self { connect: None, read: None, write: None }
    }
}

/// Represents a connection to a ADS server.
///
/// The Client's communication methods use `&self`, so that it can be freely
/// shared within one thread, or sent, between threads.  Wrappers such as
/// `Device` or `symbol::Handle` use a `&Client` as well.
pub struct Client {
    /// TCP connection (duplicated with the reader)
    socket: TcpStream,
    /// Current invoke ID (identifies the request/reply pair), incremented
    /// after each request
    invoke_id: Cell<u32>,
    /// Read timeout (actually receive timeout for the channel)
    read_timeout: Option<Duration>,
    /// The AMS address of the client
    source: AmsAddr,
    /// Sender for used Vec buffers to the reader thread
    buf_send: Sender<Vec<u8>>,
    /// Receiver for synchronous replies: used in `communicate`
    reply_recv: Receiver<Result<Vec<u8>>>,
    /// Receiver for notifications: cloned and given out to interested parties
    notif_recv: Receiver<notif::Notification>,
    /// Active notification handles: these will be closed on Drop
    notif_handles: RefCell<BTreeSet<(AmsAddr, notif::Handle)>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        // Close all open notification handles.
        let handles = std::mem::take(&mut *self.notif_handles.borrow_mut());
        for (addr, handle) in handles {
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
        // Connect, taking the timeout into account.  Unfortunately
        // connect_timeout wants a single SocketAddr.
        let addr = addr.to_socket_addrs().ctx("converting address to SocketAddr")?
                                         .next().expect("at least one SocketAddr");
        let socket = if let Some(timeout) = timeouts.connect {
            TcpStream::connect_timeout(&addr, timeout).ctx("connecting TCP socket with timeout")?
        } else {
            TcpStream::connect(&addr).ctx("connecting TCP socket")?
        };

        // Disable Nagle to ensure small requests are sent promptly; we're
        // playing ping-pong with request reply, so no pipelining.
        socket.set_nodelay(true).ctx("setting NODELAY")?;
        socket.set_write_timeout(timeouts.write).ctx("setting write timeout")?;

        // Determine our source AMS address.  If it's not specified, try to use
        // the socket's local IPv4 address, if it's IPv6 (not sure if Beckhoff
        // devices support that) use `127.0.0.1` as the last resort.
        let source = match source {
            Some(id) => id,
            None => {
                let my_addr = socket.local_addr().ctx("getting local socket address")?.ip();
                if let IpAddr::V4(ip) = my_addr {
                    let [a, b, c, d] = ip.octets();
                    // use some random ephemeral port
                    AmsAddr::new(AmsNetId::new(a, b, c, d, 1, 1), 58913)
                } else {
                    AmsAddr::new(AmsNetId::new(127, 0, 0, 1, 1, 1), 58913)
                }
            }
        };

        // Clone the socket for the reader thread and create our channels for
        // bidirectional communication.
        let socket_clone = socket.try_clone().ctx("cloning TCP socket")?;
        let (buf_send, buf_recv) = bounded(10);
        let (reply_send, reply_recv) = bounded(1);
        let (notif_send, notif_recv) = unbounded();
        let mut source_bytes = [0; 8];
        source.write_to(&mut &mut source_bytes[..]).expect("size");

        // Start the reader thread.
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
            notif_handles: RefCell::default(),
        })
    }

    /// Return the source address the client is using.
    pub fn source(&self) -> AmsAddr {
        self.source
    }

    /// Get a receiver for notifications.
    pub fn get_notification_channel(&self) -> Receiver<notif::Notification> {
        self.notif_recv.clone()
    }

    /// Return a wrapper that executes operations for a target device (known by
    /// NetID and port).
    pub fn device(&self, addr: AmsAddr) -> Device<'_> {
        Device { client: self, addr }
    }

    /// Low-level function to execute an ADS command.
    ///
    /// Writes a data from a number of input buffers, and returns data in a
    /// number of output buffers.  The latter might not be filled completely;
    /// the return value specifies the number of total valid bytes.  It is up to
    /// the caller to determine what this means in terms of the passed buffers.
    pub fn communicate(&self,
                       cmd: Command,
                       target: AmsAddr,
                       data_in: &[&[u8]],
                       data_out: &mut [&mut [u8]]) -> Result<usize> {
        // Increase the invoke ID.  We could also generate a random u32, but
        // this way the sequence of packets can be tracked.
        self.invoke_id.set(self.invoke_id.get().wrapping_add(1));

        // The data we send is the sum of all data_in buffers.
        let data_in_len = data_in.iter().map(|v| v.len()).sum::<usize>();

        // Create outgoing header.
        let header = AdsHeader {
            padding:     0,
            length:      U32::new((AMS_HEADER_SIZE + data_in_len).try_into()?),
            dest_netid:  target.netid(),
            dest_port:   U16::new(target.port()),
            src_netid:   self.source.netid(),
            src_port:    U16::new(self.source.port()),
            command:     U16::new(cmd as u16),
            state_flags: U16::new(4),                   // state flags (4 = send command)
            data_length: U32::new(data_in_len as u32),  // overflow checked above
            error_code:  U32::new(0),
            invoke_id:   U32::new(self.invoke_id.get()),
        };

        // Collect the outgoing data.  Note, allocating a Vec and calling
        // `socket.write_all` only once is faster than writing in multiple
        // steps, even with TCP_NODELAY.
        let mut request = Vec::with_capacity(HEADER_SIZE + data_in_len);
        request.extend_from_slice(header.as_bytes());
        for buf in data_in {
            request.extend_from_slice(buf);
        }
        // &T impls Write for T: Write, so no &mut self required.
        (&self.socket).write_all(&request).ctx("sending request")?;

        // Get a reply from the reader thread, with timeout or not.
        let reply = if let Some(tmo) = self.read_timeout {
            self.reply_recv.recv_timeout(tmo).map_err(|_| io::ErrorKind::TimedOut.into())
                                             .ctx("receiving reply from channel")?
        } else {
            self.reply_recv.recv().map_err(|_| io::ErrorKind::UnexpectedEof.into())
                                  .ctx("receiving reply from channel")?
        }?;

        // Validate the incoming reply.  The reader thread already made sure that
        // it is consistent and addressed to us.

        // The source netid/port must match what we sent.
        if reply[14..22] != request[6..14] {
            return Err(Error::Reply(cmd.action(), "unexpected source address", 0));
        }
        // Read the other fields we need.
        assert!(reply.len() >= HEADER_SIZE);
        // TODO: use AdsHeader::read_from with zerocopy 0.6
        let mut ptr = &reply[22..];
        let ret_cmd = ptr.read_u16::<LE>().expect("size");
        let state_flags = ptr.read_u16::<LE>().expect("size");
        let data_len = ptr.read_u32::<LE>().expect("size");
        let error_code = ptr.read_u32::<LE>().expect("size");
        let invoke_id = ptr.read_u32::<LE>().expect("size");
        let result = if reply.len() >= HEADER_SIZE + 4 {
            ptr.read_u32::<LE>().expect("size")
        } else {
            0  // this must be because an error code is already set
        };

        // Command must match.
        if ret_cmd != cmd as u16 {
            return Err(Error::Reply(cmd.action(), "unexpected command", ret_cmd.into()));
        }
        // State flags must be "4 | 1".
        if state_flags != 5 {
            return Err(Error::Reply(cmd.action(), "unexpected state flags", state_flags.into()));
        }
        // Invoke ID must match what we sent.
        if invoke_id != self.invoke_id.get() {
            return Err(Error::Reply(cmd.action(), "unexpected invoke ID", invoke_id));
        }
        // Check error code in AMS header.
        if error_code != 0 {
            return ads_error(cmd.action(), error_code);
        }
        // Check result field in payload, only relevant if error_code == 0.
        if result != 0 {
            return ads_error(cmd.action(), result);
        }

        // If we don't want return data, we're done.
        if data_out.is_empty() {
            let _ = self.buf_send.send(reply);
            return Ok(0);
        }

        // Check returned length, it needs to fill at least the first data_out
        // buffer.  This also ensures that we had a result field.
        if (data_len as usize) < data_out[0].len() + 4 {
            return Err(Error::Reply(cmd.action(), "got less data than expected", data_len));
        }

        // The pure user data length, without the result field.
        let data_len = data_len as usize - 4;

        // Distribute the data into the user output buffers, up to the returned
        // data length.
        let mut offset = HEADER_SIZE + 4;
        let mut rest_len = data_len;
        for buf in data_out {
            let n = buf.len().min(rest_len);
            buf[..n].copy_from_slice(&reply[offset..][..n]);
            offset += n;
            rest_len -= n;
            if rest_len == 0 {
                break;
            }
        }

        // Send back the Vec buffer to the reader thread.
        let _ = self.buf_send.send(reply);

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
    reply_send: Sender<Result<Vec<u8>>>,
    notif_send: Sender<notif::Notification>,
}

impl Reader {
    fn run(mut self) {
        self.run_inner();
        // We can't do much here.  But try to shut down the socket so that
        // the main client can't be used anymore either.
        let _ = self.socket.shutdown(Shutdown::Both);
    }

    fn run_inner(&mut self) {
        loop {
            // Get a buffer from the free-channel or create a new one.
            let mut buf = self.buf_recv.try_recv()
                                       .unwrap_or_else(|_| Vec::with_capacity(DEFAULT_BUFFER_SIZE));

            // Read a header from the socket.
            buf.resize(HEADER_SIZE, 0);
            if self.socket.read_exact(&mut buf).ctx("reading packet header").is_err() {
                // Not sending an error back; we don't know if something was
                // requested or the socket was just closed from either side.
                return;
            }

            // If the header isn't self-consistent, abort the connection.
            let packet_length = LE::read_u32(&buf[2..6]) as usize;
            let rest_length = LE::read_u32(&buf[26..30]) as usize;

            // First two bytes must be zero, and the two length fields must agree.
            if buf[..2] != [0, 0] || rest_length != packet_length - AMS_HEADER_SIZE {
                let _ = self.reply_send.send(Err(Error::Reply("reading packet",
                                                              "inconsistent packet", 0)));
                return;
            }

            // Read the rest of the message.
            buf.resize(HEADER_SIZE + rest_length, 0);
            if let Err(e) = self.socket.read_exact(&mut buf[HEADER_SIZE..]).ctx("reading packet data") {
                let _ = self.reply_send.send(Err(e));
                return;
            }

            // Check that the packet is meant for us.
            if buf[6..14] != self.source {
                continue;
            }

            // If it looks like a reply, send it back to the requesting thread,
            // it will handle further validation.
            if LE::read_u16(&buf[22..24]) != Command::Notification as u16 {
                if self.reply_send.send(Ok(buf)).is_err() {
                    // Client must have been shut down.
                    return;
                }
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
            if let Ok(notif) = notif::Notification::new(buf) {
                self.notif_send.send(notif).expect("never disconnects");
            }
        }
    }
}

/// A `Client` wrapper that talks to a specific ADS device.
#[derive(Clone, Copy)]
pub struct Device<'c> {
    /// The underlying `Client`.
    pub client: &'c Client,
    addr: AmsAddr,
}

impl<'c> Device<'c> {
    /// Read the device's name + version.
    pub fn get_info(&self) -> Result<DeviceInfo> {
        let mut data = DeviceInfoRaw::default();
        self.client.communicate(Command::DevInfo, self.addr,
                                &[], &mut [data.as_bytes_mut()])?;

        // Decode the name string, which is null-terminated.  Technically it's
        // Windows-1252, but in practice no non-ASCII occurs.
        let name = data.name.iter().take_while(|&&ch| ch > 0)
                                   .map(|&ch| ch as char).collect::<String>();
        Ok(DeviceInfo {
            major: data.major,
            minor: data.minor,
            version: data.version.get(),
            name,
        })
    }

    /// Read some data at a given index group/offset.
    pub fn read(&self, index_group: u32, index_offset: u32, data: &mut [u8]) -> Result<usize> {
        let header = IndexLength {
            index_group:  U32::new(index_group),
            index_offset: U32::new(index_offset),
            length:       U32::new(data.len().try_into()?),
        };
        let mut read_len = U32::<LE>::new(0);

        self.client.communicate(Command::Read, self.addr,
                                &[header.as_bytes()], &mut [read_len.as_bytes_mut(), data])?;

        Ok(read_len.get() as usize)
    }

    /// Read some data at a given index group/offset.
    pub fn read_exact(&self, index_group: u32, index_offset: u32, data: &mut [u8]) -> Result<()> {
        let len = self.read(index_group, index_offset, data)?;
        if len != data.len() {
            return Err(Error::Reply("read data", "got less data than expected", len as u32));
        }
        Ok(())
    }

    /// Write some data to a given index group/offset.
    pub fn write(&self, index_group: u32, index_offset: u32, data: &[u8]) -> Result<()> {
        let header = IndexLength {
            index_group:  U32::new(index_group),
            index_offset: U32::new(index_offset),
            length:       U32::new(data.len().try_into()?),
        };
        self.client.communicate(Command::Write, self.addr,
                                &[header.as_bytes(), data], &mut [])?;
        Ok(())
    }

    /// Write some data to a given index group/offset and then read back some
    /// reply from there.  This is not the same as a write() followed by read();
    /// it is used as a kind of RPC call.
    pub fn write_read(&self, index_group: u32, index_offset: u32, write_data: &[u8],
                      read_data: &mut [u8]) -> Result<usize> {
        let header = IndexLengthRW {
            index_group:  U32::new(index_group),
            index_offset: U32::new(index_offset),
            read_length:  U32::new(read_data.len().try_into()?),
            write_length: U32::new(write_data.len().try_into()?),
        };
        let mut read_len = U32::<LE>::new(0);
        self.client.communicate(Command::ReadWrite, self.addr,
                                &[header.as_bytes(), write_data],
                                &mut [read_len.as_bytes_mut(), read_data])?;
        Ok(read_len.get() as usize)
    }

    /// Return the ADS and device state of the device.
    pub fn get_state(&self) -> Result<(AdsState, u16)> {
        let mut state = ReadState::default();
        self.client.communicate(Command::ReadState, self.addr,
                                &[], &mut [state.as_bytes_mut()])?;

        // Convert ADS state to the enum type
        let ads_state = AdsState::try_from(state.ads_state.get())
            .map_err(|e| Error::Reply("read state", e, state.ads_state.get().into()))?;

        Ok((ads_state, state.dev_state.get()))
    }

    /// (Try to) set the ADS and device state of the device.
    pub fn write_control(&self, ads_state: AdsState, dev_state: u16) -> Result<()> {
        let data = WriteControl {
            ads_state:   U16::new(ads_state as _),
            dev_state:   U16::new(dev_state),
            data_length: U32::new(0),
        };
        self.client.communicate(Command::WriteControl, self.addr,
                                &[data.as_bytes()], &mut [])?;
        Ok(())
    }

    /// Add a notification handle for some index group/offset.
    ///
    /// Notifications are delivered via a MPMC channel whose reading end can be
    /// obtained from `get_notification_channel` on the `Client` object.
    /// The returned `Handle` can be used to check which notification has fired.
    ///
    /// If the notification is not deleted explictly using `delete_notification`
    /// and the `Handle`, it is deleted when the `Client` object is dropped.
    pub fn add_notification(&self, index_group: u32, index_offset: u32,
                            attributes: &notif::Attributes) -> Result<notif::Handle> {
        let data = AddNotif {
            index_group:  U32::new(index_group),
            index_offset: U32::new(index_offset),
            length:       U32::new(attributes.length.try_into()?),
            trans_mode:   U32::new(attributes.trans_mode as u32),
            max_delay:    U32::new(attributes.max_delay.as_millis().try_into()?),
            cycle_time:   U32::new(attributes.cycle_time.as_millis().try_into()?),
            reserved:     [0; 16],
        };
        let mut handle = U32::<LE>::new(0);
        self.client.communicate(Command::AddNotification, self.addr,
                                &[data.as_bytes()], &mut [handle.as_bytes_mut()])?;
        self.client.notif_handles.borrow_mut().insert((self.addr, handle.get()));
        Ok(handle.get())
    }

    /// Delete a notification with given handle.
    pub fn delete_notification(&self, handle: notif::Handle) -> Result<()> {
        self.client.communicate(Command::DeleteNotification, self.addr,
                                &[U32::<LE>::new(handle).as_bytes()], &mut [])?;
        self.client.notif_handles.borrow_mut().remove(&(self.addr, handle));
        Ok(())
    }
}

/// Device info returned from an ADS server.
#[derive(Debug)]
pub struct DeviceInfo {
    /// Name of the ADS device/service.
    pub name: String,
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Build version.
    pub version: u16,
}

/// The ADS state of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
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
    type Error = &'static str;

    fn try_from(value: u16) -> std::result::Result<Self, &'static str> {
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
            _  => return Err("invalid state constant")
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

// Structures used in communication, not exposed to user,
// but pub(crate) for the test suite.

// TODO: with zerocopy 0.6+, use new_zeroed instead of deriving Default

#[derive(AsBytes, FromBytes, Debug, Default)]
#[repr(C)]
pub(crate) struct AdsHeader {
    pub padding:     u16,
    pub length:      U32<LE>,
    pub dest_netid:  AmsNetId,
    pub dest_port:   U16<LE>,
    pub src_netid:   AmsNetId,
    pub src_port:    U16<LE>,
    pub command:     U16<LE>,
    pub state_flags: U16<LE>,
    pub data_length: U32<LE>,
    pub error_code:  U32<LE>,
    pub invoke_id:   U32<LE>,
}

#[derive(FromBytes, AsBytes, Default)]
#[repr(C)]
pub(crate) struct DeviceInfoRaw {
    pub major:   u8,
    pub minor:   u8,
    pub version: U16<LE>,
    pub name:    [u8; 16],
}

#[derive(FromBytes, AsBytes, Default)]
#[repr(C)]
pub(crate) struct IndexLength {
    pub index_group:  U32<LE>,
    pub index_offset: U32<LE>,
    pub length:       U32<LE>,
}

#[derive(FromBytes, AsBytes, Default)]
#[repr(C)]
pub(crate) struct IndexLengthRW {
    pub index_group:  U32<LE>,
    pub index_offset: U32<LE>,
    pub read_length:  U32<LE>,
    pub write_length: U32<LE>,
}

#[derive(FromBytes, AsBytes, Default)]
#[repr(C)]
pub(crate) struct ReadState {
    pub ads_state:   U16<LE>,
    pub dev_state:   U16<LE>,
}

#[derive(FromBytes, AsBytes, Default)]
#[repr(C)]
pub(crate) struct WriteControl {
    pub ads_state:   U16<LE>,
    pub dev_state:   U16<LE>,
    pub data_length: U32<LE>,
}

#[derive(FromBytes, AsBytes, Default)]
#[repr(C)]
pub(crate) struct AddNotif {
    pub index_group:  U32<LE>,
    pub index_offset: U32<LE>,
    pub length:       U32<LE>,
    pub trans_mode:   U32<LE>,
    pub max_delay:    U32<LE>,
    pub cycle_time:   U32<LE>,
    pub reserved:     [u8; 16],
}
