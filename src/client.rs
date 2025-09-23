//! Contains the TCP client to connect to an ADS server.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::fmt::Debug;
use std::io::{ErrorKind, Read, Write};
use std::mem::size_of;
use std::net::{IpAddr, Shutdown, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::RwLock;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::Duration;

use byteorder::{ByteOrder, LE};
use crossbeam_channel::{unbounded, Receiver, Sender};
use itertools::Itertools;

use crate::errors::{ads_error, ErrContext};
use crate::{notif, symbol};
use crate::{AmsAddr, AmsNetId, Error, Result};

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

type PendingMap = Arc<Mutex<BTreeMap<u32, oneshot::Sender<Result<(AdsHeader, Vec<u8>)>>>>>;

type NotifCallback = Box<dyn for<'data> Fn(&'data notif::Sample) + Send + Sync>;
type CallbackMap = Arc<RwLock<BTreeMap<notif::Handle, BTreeMap<u32, NotifCallback>>>>;

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

/// Size of the AMS/TCP + AMS headers
// https://infosys.beckhoff.com/content/1033/tc3_ads_intro/115845259.html?id=6032227753916597086
pub(crate) const AMS_TCP_HEADER_SIZE: usize = 6;
pub(crate) const AMS_HEADER_SIZE: usize = 32;
pub(crate) const ADS_HEADER_SIZE: usize = AMS_TCP_HEADER_SIZE + AMS_HEADER_SIZE; // including AMS/TCP header

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

/// Specifies the source AMS address to use.
#[derive(Clone, Copy, Debug)]
pub enum Source {
    /// Auto-generate a source address from the local address and a random port.
    Auto,
    /// Use a specified source address.
    Addr(AmsAddr),
    /// Request to open a port in the connected router and get the address from
    /// it.  This is necessary when connecting to a local PLC on `127.0.0.1`.
    Request,
}

/// A unique handle to a callback registration held by an `ads::Client`
/// instance.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct CallbackHandle {
  notif_handle: u32,
  cb_handle: u32
}

impl CallbackHandle {
    /// Returns the underlying notification handle
    pub fn notification_handle(&self) -> notif::Handle {
        self.notif_handle
    }
}

/// Represents a connection to a ADS server.
///
/// The Client's communication methods use `&self`, so that it can be freely
/// shared within one thread, or sent, between threads.  Wrappers such as
/// `Device` or `symbol::Handle` use a `&Client` as well.
pub struct Client {
    /// TCP connection (duplicated with the reader)
    socket: Mutex<TcpStream>,
    /// Current invoke ID (identifies the request/reply pair), incremented
    /// after each request
    invoke_id: AtomicU32,
    /// Read timeout (actually receive timeout for the channel)
    read_timeout: Option<Duration>,
    /// The AMS address of the client
    source: AmsAddr,
    /// Active requests
    pending: PendingMap,
    /// Receiver for notifications: cloned and given out to interested parties
    notif_recv: Receiver<notif::Notification>,
    /// Active notification handles: these will be closed on Drop
    notif_handles: Mutex<BTreeSet<(AmsAddr, notif::Handle)>>,
    /// IO receiver
    receiver: ClientReceiver,
    /// Resources associated with a notification worker loop
    notif_work: Mutex<Option<ClientNotificationWorker>>,
    /// If we opened our local port with the router
    source_port_opened: bool,
}

impl Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct ClientDebugAdapter<'c> {
            socket: &'c Mutex<TcpStream>,
            invoke_id: &'c AtomicU32,
            read_timeout: &'c Option<Duration>,
            source: &'c AmsAddr,
            pending: &'c PendingMap,
            notif_recv: &'c Receiver<notif::Notification>,
            notif_handles: &'c Mutex<BTreeSet<(AmsAddr, notif::Handle)>>,
            receiver: &'c ClientReceiver,
            source_port_opened: &'c bool,
        }

        let dbg_repr = ClientDebugAdapter {
            socket: &self.socket,
            invoke_id: &self.invoke_id,
            read_timeout: &self.read_timeout,
            source: &self.source,
            pending: &self.pending,
            notif_recv: &self.notif_recv,
            notif_handles: &self.notif_handles,
            receiver: &self.receiver,
            source_port_opened: &self.source_port_opened,
        };

        Debug::fmt(&dbg_repr, f)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // the notif_handles lock should only be poisioned in panics coming
        // from std code, so a panic is probably acceptable here.
        let handles = self
            .notif_handles
            .get_mut()
            .expect("notification handle cache lock was poisoned");

        // Close all open notification handles.
        for (addr, handle) in std::mem::take(handles) {
            let _ = self.device(addr).delete_notification(handle);
        }

        if let Ok(mut notif_work) = self.notif_work.lock() {
            if let Some(mut worker) = notif_work.take() {
                let _ = worker.stop();
            }
        }

        if let Ok(ref mut socket) = self.socket.lock() {
            // Remove our port from the router, if necessary.
            if self.source_port_opened {
                let mut close_port_msg = [1, 0, 2, 0, 0, 0, 0, 0];
                LE::write_u16(&mut close_port_msg[6..], self.source.port());
                let _ = socket.write_all(&close_port_msg);
            }

            let _ = socket.shutdown(Shutdown::Both);
        }

        self.receiver.stop();
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
    /// match the route entry in the server.  If `Source::Auto`, the NetID is
    /// constructed from the local IP address with .1.1 appended; if there is no
    /// IPv4 address, `127.0.0.1.1.1` is used.
    ///
    /// The AMS port of `source` is not important, as long as it is not a
    /// well-known service port; an ephemeral port number > 49152 is
    /// recommended.  If Auto, the port is set to 58913.
    ///
    /// If you are connecting to the local PLC, you need to set `source` to
    /// `Source::Request`.  This will ask the local AMS router for a new
    /// port and use it as the source port.
    ///
    /// Since all communications is supposed to be handled by an ADS router,
    /// only one TCP/ADS connection can exist between two hosts. Non-TwinCAT
    /// clients should make sure to replicate this behavior, as opening a second
    /// connection will close the first.
    pub fn new(addr: impl ToSocketAddrs, timeouts: Timeouts, source: Source) -> Result<Self> {
        // Connect, taking the timeout into account.  Unfortunately
        // connect_timeout wants a single SocketAddr.
        let addr = addr
            .to_socket_addrs()
            .ctx("converting address to SocketAddr")?
            .next()
            .ok_or(Error::Other("no destination address could be resolved"))?;

        let mut socket = if let Some(timeout) = timeouts.connect {
            TcpStream::connect_timeout(&addr, timeout)
                .ctx("establishing connetion to remote ADS router (with timeout)")?
        } else {
            TcpStream::connect(addr).ctx("establishing connection to remote ADS router")?
        };

        // Disable Nagle to ensure small requests are sent promptly; we're
        // playing ping-pong with request reply, so no pipelining.
        socket.set_nodelay(true).ctx("setting client socket NODELAY")?;
        socket
            .set_write_timeout(timeouts.write)
            .ctx("setting client socket write timeout")?;
        socket
            .set_read_timeout(timeouts.read)
            .ctx("setting client socket read timeout")?;

        // Determine our source AMS address.  If it's not specified, try to use
        // the socket's local IPv4 address, if it's IPv6 (not sure if Beckhoff
        // devices support that) use `127.0.0.1` as the last resort.
        //
        // If source is Request, send an AMS port open message to the connected
        // router to get our source address.  This is required when connecting
        // via localhost, apparently.
        let mut source_port_opened = false;
        let source = match source {
            Source::Addr(id) => id,
            Source::Auto => {
                let my_addr = socket.local_addr().ctx("getting local socket address")?.ip();
                if let IpAddr::V4(ip) = my_addr {
                    let [a, b, c, d] = ip.octets();
                    // use some random ephemeral port
                    AmsAddr::new(AmsNetId::new(a, b, c, d, 1, 1), 58913)
                } else {
                    AmsAddr::new(AmsNetId::new(127, 0, 0, 1, 1, 1), 58913)
                }
            }
            Source::Request => {
                let request_port_msg = [0, 16, 2, 0, 0, 0, 0, 0];
                let mut reply = [0; 14];
                socket.write_all(&request_port_msg).ctx("requesting port from router")?;
                socket.read_exact(&mut reply).ctx("requesting port from router")?;
                if reply[..6] != [0, 16, 8, 0, 0, 0] {
                    return Err(Error::Reply("requesting port", "unexpected reply header", 0));
                }
                source_port_opened = true;
                AmsAddr::new(AmsNetId::from_slice(&reply[6..12]).expect("size"), LE::read_u16(&reply[12..14]))
            }
        };

        // Clone the socket for the reader thread and create our channels for
        // bidirectional communication.
        let (notif_tx, notif_rx) = unbounded();

        let pending = PendingMap::default();

        // Start the reader thread.
        let mut receiver = ClientReceiver::default();

        receiver.start(notif_tx, &socket, pending.clone(), source);

        Ok(Client {
            source,
            receiver,
            source_port_opened,
            pending,
            socket: Mutex::new(socket),
            notif_recv: notif_rx,
            invoke_id: AtomicU32::new(1),
            read_timeout: timeouts.read,
            notif_handles: Mutex::default(),
            notif_work: Mutex::new(None),
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
    ///
    /// The local NetID `127.0.0.1.1.1` is mapped to the client's source NetID,
    /// so that you can connect to a local PLC using:
    ///
    /// ```ignore
    /// let client = Client::new("127.0.0.1", ..., Source::Request);
    /// let device = client.device(AmsAddr::new(AmsNetId::local(), 851));
    /// ```
    ///
    /// without knowing its NetID.
    pub fn device(&self, mut addr: AmsAddr) -> Device<'_> {
        if addr.netid() == AmsNetId::local() {
            addr = AmsAddr::new(self.source().netid(), addr.port());
        }
        Device { client: self, addr }
    }

    /// Low-level function to execute an ADS command.
    ///
    /// Writes a data from a number of input buffers, and returns data in a
    /// number of output buffers.  The latter might not be filled completely;
    /// the return value specifies the number of total valid bytes.  It is up to
    /// the caller to determine what this means in terms of the passed buffers.
    pub fn communicate(
        &self, cmd: Command, target: AmsAddr, payload_bufs: &[&[u8]], result_bufs: &mut [&mut [u8]],
    ) -> Result<usize> {
        // Increase the invoke ID.  We could also generate a random u32, but
        // this way the sequence of packets can be tracked.
        let dispatched_invoke_id = self.invoke_id.fetch_add(1, Ordering::Relaxed);

        // The data we send is the sum of all data_in buffers.
        let payload_len = payload_bufs.iter().map(|v| v.len()).sum::<usize>();

        // Create outgoing header.
        let ads_data_len = AMS_HEADER_SIZE + payload_len;
        let header = AdsHeader {
            ams_cmd: 0, // send command
            length: U32::new(ads_data_len.try_into()?),
            dest_netid: target.netid(),
            dest_port: U16::new(target.port()),
            src_netid: self.source.netid(),
            src_port: U16::new(self.source.port()),
            command: U16::new(cmd as u16),
            state_flags: U16::new(4), // state flags (4 = send command)
            data_length: U32::new(payload_len as u32), // overflow checked above
            error_code: U32::new(0),
            invoke_id: U32::new(dispatched_invoke_id),
        };

        let mut request_buf = Vec::with_capacity(header.length.get() as usize + payload_len);

        request_buf.extend_from_slice(header.as_bytes());

        // Collect the outgoing data.  Note, allocating a Vec and calling
        // `socket.write_all` only once is faster than writing in multiple
        // steps, even with TCP_NODELAY.
        for buf in payload_bufs.iter() {
            request_buf.extend_from_slice(buf);
        }

        let (resp_tx, resp_rx) = oneshot::channel();

        self.insert_pending_request(dispatched_invoke_id, resp_tx);

        self.socket
            .lock()
            .expect("panicked during socket write")
            .write_all(&request_buf)
            .ctx("dispatching assembled command payload")?;

        let (resp_header, resp_buf) = match self.read_timeout {
            Some(timeout) => match resp_rx.recv_timeout(timeout) {
                Ok(Ok((header, payload))) => (header, payload),

                Ok(Err(e)) => {
                    self.discard_pending_request(&dispatched_invoke_id);
                    return Err(e);
                }

                Err(oneshot::RecvTimeoutError::Disconnected) => {
                    self.discard_pending_request(&dispatched_invoke_id);
                    return Err(Error::IoSync(
                        "waiting for response to dispatched request",
                        "response channel was closed",
                        dispatched_invoke_id,
                    ));
                }

                Err(oneshot::RecvTimeoutError::Timeout) => {
                    self.discard_pending_request(&dispatched_invoke_id);
                    return Err(Error::Io(
                        "waiting for response to dispatched request",
                        ErrorKind::TimedOut.into(),
                    ));
                }
            },

            None => match resp_rx.recv() {
                Ok(Ok((header, payload))) => (header, payload),

                Ok(Err(e)) => {
                    self.discard_pending_request(&dispatched_invoke_id);
                    return Err(e);
                }

                Err(_) => {
                    self.discard_pending_request(&dispatched_invoke_id);
                    return Err(Error::IoSync(
                        "waiting for response to dispatched request",
                        "response channel was closed",
                        dispatched_invoke_id,
                    ));
                }
            },
        };

        // Validate the incoming reply. The reader thread already made sure that
        // it is consistent and addressed to us.

        // The source netid/port must match what we sent.
        if (resp_header.src_netid, resp_header.src_port.get()) != (target.netid(), target.port()) {
            return Err(Error::Reply(cmd.action(), "response wasn't from commanded target", 0));
        }

        // Command must match.
        if resp_header.command != cmd as u16 {
            return Err(Error::Reply(cmd.action(), "unexpected command", resp_header.command.into()));
        }

        // State flags must be "4 | 1".
        if resp_header.state_flags != 5 {
            return Err(Error::Reply(
                cmd.action(),
                "unexpected state flags",
                resp_header.state_flags.into(),
            ));
        }

        // Invoke ID must match what we sent.
        if resp_header.invoke_id != dispatched_invoke_id {
            return Err(Error::Reply(cmd.action(), "unexpected invoke ID", resp_header.invoke_id.get()));
        }

        // Check error code in AMS header.
        if resp_header.error_code != 0 {
            return ads_error(cmd.action(), resp_header.error_code.get());
        }

        let result = LE::read_u32(&resp_buf[..4]);

        // Check result field in payload, only relevant if error_code == 0.
        if result != 0 {
            return ads_error(cmd.action(), result);
        }

        // If we don't want return data, we're done.
        if result_bufs.is_empty() {
            return Ok(0);
        }

        // Check returned length, it needs to fill at least the first data_out
        // buffer. This also ensures that we had a result field.
        if resp_buf.len() < result_bufs[0].len() + 4 {
            return Err(Error::Reply(cmd.action(), "got less data than expected", resp_buf.len() as u32));
        }

        let resp_buf = &resp_buf[4..];

        // Distribute the data into the user output buffers, up to the returned
        // data length.
        let mut taken = 0;
        let mut rest_len = resp_buf.len();
        for buf in result_bufs {
            let n = buf.len().min(rest_len);
            let b = &resp_buf[taken..][..n];
            buf[..n].copy_from_slice(b);
            taken += n;
            rest_len -= n;
            if rest_len == 0 {
                break;
            }
        }

        // Return either the error or the length of data.
        Ok(resp_buf.len())
    }

    /// Registers a callback to be invoked when a notification is
    /// received for an already registered symbol descriptor.
    ///
    /// This is a quick method to acheive reactivity to remote symbol updates.
    /// An alternative strategy would require registerig a notification with
    /// the ADS server and filtering the global notification stream.
    ///
    /// _Note: You may see better performance using the above-mentioned_
    /// _manual reactivity strategy. See `ads::Device::add_notification` and_
    /// _`ads::Client::get_notification_channel`_
    #[must_use]
    pub fn register_callback<F>(&self, handle: notif::Handle, callback: F) -> Result<CallbackHandle>
    where
        F: for<'data> Fn(&'data notif::Sample) + Send + Sync + 'static,
    {
        self.notif_work
            .lock()
            .ctx("registering nofitication callback")?
            .get_or_insert_with(|| {
                let mut worker = ClientNotificationWorker::default();
                worker.start(self.notif_recv.clone());
                worker
            })
            .add_callback(handle, Box::new(callback))
    }

    /// Deregister a notification callback.
    /// If the handle was already removed or otherwise doesn't exist, this is
    /// a no-op and returns `Ok(())`
    pub fn remove_callback(&self, handle: CallbackHandle) -> Result<()> {
        if let Some(worker) = self.notif_work.lock().ctx("deregistering notification callback")?.as_mut() {
            worker.remove_callback(handle)
        } else {
            Ok(())
        }
    }

    fn insert_pending_request(&self, id: u32, tx: oneshot::Sender<Result<(AdsHeader, Vec<u8>)>>) {
        self.pending.lock().expect("pending command map lock poisoned").insert(id, tx);
    }

    fn discard_pending_request(&self, id: &u32) {
        self.pending.lock().expect("pending command map lock poisoned").remove_entry(id);
    }
}

#[derive(Default)]
struct ClientNotificationWorker {
    worker: Option<JoinHandle<Result<()>>>,
    callback_handle_counter: u32,
    callbacks: CallbackMap,
    recycled_handles: VecDeque<u32>
}

impl ClientNotificationWorker {
    fn start(&mut self, notif_rx: Receiver<notif::Notification>) {
        let c_callbacks = self.callbacks.clone();
        self.worker = Some(std::thread::spawn(move || Self::notif_work(notif_rx, c_callbacks)));
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(handle) = self.worker.take() {
            handle.join().unwrap_or(Ok(()))
        } else {
            Ok(())
        }
    }

    fn new_callback_handle(&mut self) -> Result<u32> {
        if let Some(handle) = self.recycled_handles.pop_front() {
            Ok(handle)
        } else {
            let cb_handle = self.callback_handle_counter;
            self.callback_handle_counter = self
                .callback_handle_counter
                .checked_add(1)
                .ok_or(Error::AllHandlesInUse)?;

            Ok(cb_handle)
        }
    }

    fn add_callback(
        &mut self, notif_handle: notif::Handle, callback: NotifCallback,
    ) -> Result<CallbackHandle> {
        let cb_handle = self.new_callback_handle()?;

        let recycled_handles = &mut self.recycled_handles;
        let mut cbs = self.callbacks
            .write()
            .ctx("registering notificaiton callback")
            .inspect_err(|_| recycled_handles.push_back(cb_handle))?;

        if let Some(cb_map) = cbs.get_mut(&notif_handle) {
            cb_map.insert(cb_handle, callback);
        } else {
            let mut map = BTreeMap::new();
            map.insert(cb_handle, callback);
            cbs.insert(notif_handle, map);
        }

        Ok(CallbackHandle { notif_handle, cb_handle })
    }

    fn remove_callback(&mut self, handle: CallbackHandle) -> Result<()> {
        let CallbackHandle { notif_handle, cb_handle } = handle;
        let mut cbs = self.callbacks.write().ctx("deregistering notification callback")?;

        if let Some(cb_map) = cbs.get_mut(&notif_handle) {
            let _ = cb_map.remove(&cb_handle);
            self.recycled_handles.push_back(cb_handle);
        }

        Ok(())
    }

    fn notif_work(recv: Receiver<notif::Notification>, callbacks: CallbackMap) -> Result<()> {
        for notif in recv.iter() {
            let cbs = callbacks.read().ctx("invoking notification callbacks")?;

            for sample in notif.samples() {
                let cb_map = match cbs.get(&sample.handle) {
                    Some(map) => map,
                    None => continue,
                };

                for (_, cb) in cb_map.iter() {
                    cb(&sample)
                }
            }
        }

        Ok(())
    }
}

impl Drop for ClientNotificationWorker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// Implementation detail: reader thread that takes replies and notifications
// and distributes them accordingly.
#[derive(Debug, Default)]
struct ClientReceiver {
    handle: Option<JoinHandle<Result<()>>>,
}

impl ClientReceiver {
    fn start(
        &mut self, mut notif_tx: Sender<notif::Notification>, socket: &TcpStream, pending: PendingMap,
        source: AmsAddr,
    ) {
        let mut socket = socket.try_clone().expect("socket cloning failed");

        let rx_worker = std::thread::spawn(move || {
            let result = Self::reader_work(source, pending.clone(), &mut socket, &mut notif_tx);

            let _ = socket.shutdown(Shutdown::Both);

            if let Ok(ref mut pending) = pending.lock() {
                let keys = pending.keys().cloned().collect_vec();
                for key in keys {
                    if let Some(channel) = pending.remove(&key) {
                        let err = if let Err(e) = &result {
                            Err(e.clone())
                        } else {
                            Err(Error::Reply(
                                "handling clean shutdown",
                                "pending request at client shutdown",
                                0,
                            ))
                        };

                        let _ = channel.send(err);
                    };
                }
            }

            result
        });

        let _ = self.handle.insert(rx_worker);
    }

    fn stop(&mut self) -> Option<Result<()>> {
        self.handle.take()?.join().ok()
    }

    fn reader_work(
        source: AmsAddr, pending: PendingMap, socket_rx: &mut TcpStream,
        notif_tx: &mut Sender<notif::Notification>,
    ) -> Result<()> {
        loop {
            let mut ads_header_buf = [0u8; ADS_HEADER_SIZE];

            socket_rx.read_exact(&mut ads_header_buf[..6]).ctx("receiving AMS/TCP header")?;

            let packet_len = LE::read_u32(&ads_header_buf[2..6]);

            let ads_header: AdsHeader = match packet_len {
                0..=31 => {
                    let mut discard = [0u8; 31];

                    socket_rx
                        .read_exact(&mut discard[..packet_len as usize])
                        .ctx("discarding bad data")?;

                    continue;
                }

                _ => {
                    socket_rx.read_exact(&mut ads_header_buf[6..]).ctx("receiving AMS header")?;

                    AdsHeader::read_from_bytes(&ads_header_buf[..ADS_HEADER_SIZE])
                        .map_err(|_| {
                            <ErrorKind as Into<std::io::Error>>::into(std::io::ErrorKind::InvalidData)
                        })
                        .ctx("decoding AMS header")?
                }
            };

            let payload_len = ads_header.data_length.get();

            let mut payload_buf = vec![0u8; payload_len as usize];

            socket_rx.read_exact(&mut payload_buf).ctx("receiving Ads data payload")?;

            // Reserved bytes should be well-known
            // Anything else might be invalid data
            match LE::read_u16(ads_header_buf.as_slice()) {
                0 => (),
                1 | 4096..=4098 => continue,
                unknown => {
                    return Err(Error::Reply(
                        "interpreting received AMS packet",
                        "invalid packet",
                        unknown as _,
                    ))
                }
            }

            // If the header length fields aren't self-consistent, abort the connection.
            if payload_len != packet_len - AMS_HEADER_SIZE as u32 {
                return Err(Error::Reply(
                    "interpreting received AMS packet",
                    "AMS/TCP header and AMS header contain inconsistent data",
                    0,
                ));
            }

            // Check that the packet is meant for us.
            if (ads_header.dest_netid, ads_header.dest_port.get()) != (source.netid(), source.port()) {
                continue;
            }

            let invoke_id = ads_header.invoke_id.get();

            // If it looks like a reply, send it back to the requesting thread,
            // it will handle further validation.
            if ads_header.command != Command::Notification as u16 {
                match pending.lock().expect("pending map lock poisoned").remove_entry(&invoke_id) {
                    Some((_, tx)) => {
                        if tx.send(Ok((ads_header, payload_buf))).is_err() {
                            return Err(Error::IoSync(
                                "settling pending request",
                                "channel closed, couldn't dispatch response",
                                invoke_id,
                            ));
                        }
                    }

                    _ => {
                        return Err(Error::Reply(
                            "settling pending request",
                            "invalid invoke id received from server, aborting connection",
                            invoke_id,
                        ))
                    }
                };
            } else {
                let notif_payload_len = LE::read_u32(&payload_buf);
                if ads_header.state_flags != 4
                    || ads_header.error_code != 0
                    || notif_payload_len != payload_len - 4
                    || notif_payload_len < 4
                {
                    continue;
                }

                // Send the notification to whoever wants to receive it.
                if let Ok(notif) =
                    notif::Notification::new([ads_header_buf.as_slice(), &payload_buf].concat())
                {
                    notif_tx.send(notif).expect("never disconnects");
                }
            }
        }
    }
}

impl Drop for ClientReceiver {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A `Client` wrapper that talks to a specific ADS device.
#[derive(Clone, Copy)]
pub struct Device<'c> {
    /// The underlying `Client`.
    pub client: &'c Client,
    addr: AmsAddr,
}

impl Device<'_> {
    /// Read the device's name + version.
    pub fn get_info(&self) -> Result<DeviceInfo> {
        let mut data = DeviceInfoRaw::new_zeroed();
        self.client
            .communicate(Command::DevInfo, self.addr, &[], &mut [data.as_mut_bytes()])?;

        // Decode the name string, which is null-terminated.  Technically it's
        // Windows-1252, but in practice no non-ASCII occurs.
        let name = data
            .name
            .iter()
            .take_while(|&&ch| ch > 0)
            .map(|&ch| ch as char)
            .collect::<String>();
        Ok(DeviceInfo { major: data.major, minor: data.minor, version: data.version.get(), name })
    }

    /// Read some data at a given index group/offset.  Returned data can be shorter than
    /// the buffer, the length is the return value.
    pub fn read(&self, index_group: u32, index_offset: u32, data: &mut [u8]) -> Result<usize> {
        let header = IndexLength {
            index_group: U32::new(index_group),
            index_offset: U32::new(index_offset),
            length: U32::new(data.len().try_into()?),
        };

        let mut read_len = U32::new(0);

        self.client.communicate(
            Command::Read,
            self.addr,
            &[header.as_bytes()],
            &mut [read_len.as_mut_bytes(), data],
        )?;

        Ok(read_len.get() as usize)
    }

    /// Read some data at a given index group/offset, ensuring that the returned data has
    /// exactly the size of the passed buffer.
    pub fn read_exact(&self, index_group: u32, index_offset: u32, data: &mut [u8]) -> Result<()> {
        let len = self.read(index_group, index_offset, data)?;
        if len != data.len() {
            return Err(Error::Reply("read data", "got less data than expected", len as u32));
        }
        Ok(())
    }

    /// Read data of given type.
    ///
    /// Any type that supports `zerocopy::FromBytes` can be read.  You can also
    /// derive that trait on your own structures and read structured data
    /// directly from the symbol.
    ///
    /// Note: to be independent of the host's byte order, use the integer types
    /// defined in `zerocopy::byteorder`.
    pub fn read_value<T: Default + IntoBytes + FromBytes>(
        &self, index_group: u32, index_offset: u32,
    ) -> Result<T> {
        let mut buf = T::default();
        self.read_exact(index_group, index_offset, buf.as_mut_bytes())?;
        Ok(buf)
    }

    /// Read multiple index groups/offsets with one ADS request (a "sum-up" request).
    ///
    /// This function only returns Err on errors that cause the whole sum-up
    /// request to fail (e.g. if the device doesn't support such requests).  If
    /// the request as a whole succeeds, each single read can have returned its
    /// own error.
    ///
    /// The returned data can be shorter than the buffer in each request.  The
    /// [`ReadRequest::data`] method will return either the properly truncated
    /// returned data or the error for each read.
    ///
    /// Example:
    /// ```no_run
    /// # fn main() -> ads::Result<()> {
    /// # use ads::client::*;
    /// # let client = Client::new(("", ads::PORT), ads::Timeouts::none(), ads::Source::Auto)?;
    /// # let device = client.device(ads::AmsAddr::new(Default::default(), 0));
    /// # let (ix1, ix2, off1, off2) = (0, 0, 0, 0);
    /// // create buffers
    /// let mut buf_1 = [0; 128];  // request reading 128 bytes each,
    /// let mut buf_2 = [0; 128];  // from two indices
    /// // create the request structures
    /// let req_1 = ReadRequest::new(ix1, off1, &mut buf_1);
    /// let req_2 = ReadRequest::new(ix2, off2, &mut buf_2);
    /// let mut requests = [req_1, req_2];
    /// // execute the multi-request on the remote end
    /// device.read_multi(&mut requests)?;
    /// // extract the resulting data, checking individual reads for
    /// // errors and getting the returned data otherwise
    /// let res_1 = requests[0].data()?;
    /// let res_2 = requests[1].data()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_multi(&self, requests: &mut [ReadRequest]) -> Result<()> {
        let nreq = requests.len();
        let rlen = requests.iter().map(|r| size_of::<ResultLength>() + r.rbuf.len()).sum::<usize>();
        let wlen = size_of::<IndexLength>() * nreq;
        let header = IndexLengthRW {
            // using SUMUP_READ_EX_2 since would return the actual returned
            // number of bytes, and no empty bytes if the read is short,
            // but then we'd have to reshuffle the buffers
            index_group: U32::new(crate::index::SUMUP_READ_EX),
            index_offset: U32::new(nreq as u32),
            read_length: U32::new(rlen.try_into()?),
            write_length: U32::new(wlen.try_into()?),
        };
        let mut read_len = U32::new(0);
        let mut w_buffers = vec![header.as_bytes()];
        let mut r_buffers = (0..2 * nreq + 1).map(|_| &mut [][..]).collect_vec();
        r_buffers[0] = read_len.as_mut_bytes();
        for (i, req) in requests.iter_mut().enumerate() {
            w_buffers.push(req.req.as_bytes());
            r_buffers[1 + i] = req.res.as_mut_bytes();
            r_buffers[1 + nreq + i] = req.rbuf;
        }
        self.client
            .communicate(Command::ReadWrite, self.addr, &w_buffers, &mut r_buffers)?;
        Ok(())
    }

    /// Write some data to a given index group/offset.
    pub fn write(&self, index_group: u32, index_offset: u32, data: &[u8]) -> Result<()> {
        let header = IndexLength {
            index_group: U32::new(index_group),
            index_offset: U32::new(index_offset),
            length: U32::new(data.len().try_into()?),
        };
        self.client
            .communicate(Command::Write, self.addr, &[header.as_bytes(), data], &mut [])?;
        Ok(())
    }

    /// Write data of given type.
    ///
    /// See `read_value` for details.
    pub fn write_value<T: IntoBytes + Immutable>(
        &self, index_group: u32, index_offset: u32, value: &T,
    ) -> Result<()> {
        self.write(index_group, index_offset, value.as_bytes())
    }

    /// Write multiple index groups/offsets with one ADS request (a "sum-up" request).
    ///
    /// This function only returns Err on errors that cause the whole sum-up
    /// request to fail (e.g. if the device doesn't support such requests).  If
    /// the request as a whole succeeds, each single write can have returned its
    /// own error.  To retrieve and handle them, the [`WriteRequest::ensure`]
    /// method should be called on each request.
    ///
    /// Example:
    /// ```no_run
    /// # fn main() -> ads::Result<()> {
    /// # use ads::client::*;
    /// # let client = Client::new(("", ads::PORT), ads::Timeouts::none(), ads::Source::Auto)?;
    /// # let device = client.device(ads::AmsAddr::new(Default::default(), 0));
    /// # let (ix1, ix2, off1, off2) = (0, 0, 0, 0);
    /// // create buffers
    /// let buf_1 = [1, 5, 7, 10];  // request writing 4 bytes each,
    /// let buf_2 = [0, 8, 9, 11];  // to two indices
    /// // create the request structures
    /// let req_1 = WriteRequest::new(ix1, off1, &buf_1);
    /// let req_2 = WriteRequest::new(ix2, off2, &buf_2);
    /// let mut requests = [req_1, req_2];
    /// // execute the multi-request on the remote end
    /// device.write_multi(&mut requests)?;
    /// // check the individual writes for errors
    /// requests[0].ensure()?;
    /// requests[1].ensure()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_multi(&self, requests: &mut [WriteRequest]) -> Result<()> {
        let nreq = requests.len();
        let rlen = size_of::<u32>() * nreq;
        let wlen = requests.iter().map(|r| size_of::<IndexLength>() + r.wbuf.len()).sum::<usize>();
        let header = IndexLengthRW {
            index_group: U32::new(crate::index::SUMUP_WRITE),
            index_offset: U32::new(nreq as u32),
            read_length: U32::new(rlen.try_into()?),
            write_length: U32::new(wlen.try_into()?),
        };
        let mut read_len = U32::new(0);
        let mut w_buffers = vec![&[][..]; 2 * nreq + 1];
        let mut r_buffers = vec![read_len.as_mut_bytes()];
        w_buffers[0] = header.as_bytes();
        for (i, req) in requests.iter_mut().enumerate() {
            w_buffers[1 + i] = req.req.as_bytes();
            w_buffers[1 + nreq + i] = req.wbuf;
            r_buffers.push(req.res.as_mut_bytes());
        }
        self.client
            .communicate(Command::ReadWrite, self.addr, &w_buffers, &mut r_buffers)?;
        Ok(())
    }

    /// Write some data to a given index group/offset and then read back some
    /// reply from there.  This is not the same as a write() followed by read();
    /// it is used as a kind of RPC call.
    pub fn write_read(
        &self, index_group: u32, index_offset: u32, write_data: &[u8], read_data: &mut [u8],
    ) -> Result<usize> {
        let header = IndexLengthRW {
            index_group: U32::new(index_group),
            index_offset: U32::new(index_offset),
            read_length: U32::new(read_data.len().try_into()?),
            write_length: U32::new(write_data.len().try_into()?),
        };
        let mut read_len = U32::new(0);
        self.client.communicate(
            Command::ReadWrite,
            self.addr,
            &[header.as_bytes(), write_data],
            &mut [read_len.as_mut_bytes(), read_data],
        )?;
        Ok(read_len.get() as usize)
    }

    /// Like `write_read`, but ensure the returned data length matches the output buffer.
    pub fn write_read_exact(
        &self, index_group: u32, index_offset: u32, write_data: &[u8], read_data: &mut [u8],
    ) -> Result<()> {
        let len = self.write_read(index_group, index_offset, write_data, read_data)?;
        if len != read_data.len() {
            return Err(Error::Reply("write/read data", "got less data than expected", len as u32));
        }
        Ok(())
    }

    /// Write multiple index groups/offsets with one ADS request (a "sum-up" request).
    ///
    /// This function only returns Err on errors that cause the whole sum-up
    /// request to fail (e.g. if the device doesn't support such requests).  If
    /// the request as a whole succeeds, each single write/read can have
    /// returned its own error.  The [`WriteReadRequest::data`] method will
    /// return either the returned data or the error for each write/read.
    ///
    /// See [`Device::read_multi`] or [`Device::write_multi`] for analogous usage examples.
    pub fn write_read_multi(&self, requests: &mut [WriteReadRequest]) -> Result<()> {
        let nreq = requests.len();
        let rlen = requests.iter().map(|r| size_of::<ResultLength>() + r.rbuf.len()).sum::<usize>();
        let wlen = requests
            .iter()
            .map(|r| size_of::<IndexLengthRW>() + r.wbuf.len())
            .sum::<usize>();
        let header = IndexLengthRW {
            index_group: U32::new(crate::index::SUMUP_READWRITE),
            index_offset: U32::new(nreq as u32),
            read_length: U32::new(rlen.try_into()?),
            write_length: U32::new(wlen.try_into()?),
        };
        let mut read_len = U32::new(0);
        let mut w_buffers = vec![&[][..]; 2 * nreq + 1];
        let mut r_buffers = (0..2 * nreq + 1).map(|_| &mut [][..]).collect_vec();
        w_buffers[0] = header.as_bytes();
        r_buffers[0] = read_len.as_mut_bytes();
        for (i, req) in requests.iter_mut().enumerate() {
            w_buffers[1 + i] = req.req.as_bytes();
            w_buffers[1 + nreq + i] = req.wbuf;
            r_buffers[1 + i] = req.res.as_mut_bytes();
            r_buffers[1 + nreq + i] = req.rbuf;
        }

        self.client
            .communicate(Command::ReadWrite, self.addr, &w_buffers, &mut r_buffers)?;

        // unfortunately SUMUP_READWRITE returns only the actual read bytes for each
        // request, so if there are short reads the buffers got filled wrongly
        fixup_write_read_return_buffers(requests);
        Ok(())
    }

    /// Return the ADS and device state of the device.
    pub fn get_state(&self) -> Result<(AdsState, u16)> {
        let mut state = ReadState::new_zeroed();
        self.client
            .communicate(Command::ReadState, self.addr, &[], &mut [state.as_mut_bytes()])?;

        // Convert ADS state to the enum type
        let ads_state = AdsState::try_from(state.ads_state.get())
            .map_err(|e| Error::Reply("read state", e, state.ads_state.get().into()))?;

        Ok((ads_state, state.dev_state.get()))
    }

    /// (Try to) set the ADS and device state of the device.
    pub fn write_control(&self, ads_state: AdsState, dev_state: u16) -> Result<()> {
        let data = WriteControl {
            ads_state: U16::new(ads_state as _),
            dev_state: U16::new(dev_state),
            data_length: U32::new(0),
        };
        self.client
            .communicate(Command::WriteControl, self.addr, &[data.as_bytes()], &mut [])?;
        Ok(())
    }

    /// Registers a notification request with the ADS server and registers a
    /// callback with local client.
    /// The callback will be invoked callback when the client receives a
    /// notification with data for the given symbol descriptors.
    ///
    /// This is a quick method to acheive reactivity to remote symbol updates.
    /// An alternative strategy would require registerig a notification with
    /// the ADS server and filtering the global notification stream.
    ///
    /// _Note: You may see better performance using the above-mentioned_
    /// _manual reactivity strategy. See `ads::Device::add_notification` and_
    /// _`ads::Client::get_notification_channel`_
    #[must_use]
    pub fn register_callback<F>(
        &self,
        index_group: u32,
        index_offset: u32,
        attributes: &notif::Attributes,
        callback: F
    ) -> Result<CallbackHandle>
    where
        F: for<'data> Fn(&'data notif::Sample) + Send + Sync + 'static
    {
        let notif_handle = self.add_notification(index_group, index_offset, attributes)?;
        self.client.register_callback(notif_handle, callback)
    }

    /// Deregister a notification callback.
    /// If the handle was already removed or otherwise doesn't exist, this is
    /// a no-op and returns `Ok(())`
    pub fn remove_callback(&self, handle: CallbackHandle) -> Result<()> {
        self.client.remove_callback(handle)
    }

    /// Add a notification handle for some index group/offset.
    ///
    /// Notifications are delivered via a MPMC channel whose reading end can be
    /// obtained from `get_notification_channel` on the `Client` object.
    /// The returned `Handle` can be used to check which notification has fired.
    ///
    /// If the notification is not deleted explictly using `delete_notification`
    /// and the `Handle`, it is deleted when the `Client` object is dropped.
    pub fn add_notification(
        &self, index_group: u32, index_offset: u32, attributes: &notif::Attributes,
    ) -> Result<notif::Handle> {
        let data = AddNotif {
            index_group: U32::new(index_group),
            index_offset: U32::new(index_offset),
            length: U32::new(attributes.length.try_into()?),
            trans_mode: U32::new(attributes.trans_mode as u32),
            max_delay: U32::new(attributes.max_delay.as_millis().try_into()?),
            cycle_time: U32::new(attributes.cycle_time.as_millis().try_into()?),
            reserved: [0; 16],
        };
        let mut handle = U32::new(0);
        self.client.communicate(
            Command::AddNotification,
            self.addr,
            &[data.as_bytes()],
            &mut [handle.as_mut_bytes()],
        )?;

        self.client
            .notif_handles
            .lock()
            .expect("notification handle cache lock poisoned")
            .insert((self.addr, handle.get()));

        Ok(handle.get())
    }

    /// Add multiple notification handles.
    ///
    /// This function only returns Err on errors that cause the whole sum-up
    /// request to fail (e.g. if the device doesn't support such requests).  If
    /// the request as a whole succeeds, each single read can have returned its
    /// own error.  The [`AddNotifRequest::handle`] method will return either
    /// the returned handle or the error for each read.
    pub fn add_notification_multi(&self, requests: &mut [AddNotifRequest]) -> Result<()> {
        let nreq = requests.len();
        let rlen = size_of::<ResultLength>() * nreq;
        let wlen = size_of::<AddNotif>() * nreq;
        let header = IndexLengthRW {
            index_group: U32::new(crate::index::SUMUP_ADDDEVNOTE),
            index_offset: U32::new(nreq as u32),
            read_length: U32::new(rlen.try_into()?),
            write_length: U32::new(wlen.try_into()?),
        };
        let mut read_len = U32::new(0);
        let mut w_buffers = vec![header.as_bytes()];
        let mut r_buffers = vec![read_len.as_mut_bytes()];
        for req in requests.iter_mut() {
            w_buffers.push(req.req.as_bytes());
            r_buffers.push(req.res.as_mut_bytes());
        }

        self.client
            .communicate(Command::ReadWrite, self.addr, &w_buffers, &mut r_buffers)?;

        for req in requests {
            if let Ok(handle) = req.handle() {
                self.client
                    .notif_handles
                    .lock()
                    .expect("notification handle cache lock poisoned")
                    .insert((self.addr, handle));
            }
        }
        Ok(())
    }

    /// Delete a notification with given handle.
    pub fn delete_notification(&self, handle: notif::Handle) -> Result<()> {
        self.client.communicate(
            Command::DeleteNotification,
            self.addr,
            &[U32::new(handle).as_bytes()],
            &mut [],
        )?;

        self.client
            .notif_handles
            .lock()
            .expect("notification handle cache lock poisoned")
            .remove(&(self.addr, handle));

        Ok(())
    }

    /// Delete multiple notification handles.
    ///
    /// This function only returns Err on errors that cause the whole sum-up
    /// request to fail (e.g. if the device doesn't support such requests).  If
    /// the request as a whole succeeds, each single read can have returned its
    /// own error.  The [`DelNotifRequest::ensure`] method will return either the
    /// returned data or the error for each read.
    pub fn delete_notification_multi(&self, requests: &mut [DelNotifRequest]) -> Result<()> {
        let nreq = requests.len();
        let rlen = size_of::<u32>() * nreq;
        let wlen = size_of::<u32>() * nreq;
        let header = IndexLengthRW {
            index_group: U32::new(crate::index::SUMUP_DELDEVNOTE),
            index_offset: U32::new(nreq as u32),
            read_length: U32::new(rlen.try_into()?),
            write_length: U32::new(wlen.try_into()?),
        };
        let mut read_len = U32::new(0);
        let mut w_buffers = vec![header.as_bytes()];
        let mut r_buffers = vec![read_len.as_mut_bytes()];
        for req in requests.iter_mut() {
            w_buffers.push(req.req.as_bytes());
            r_buffers.push(req.res.as_mut_bytes());
        }

        self.client
            .communicate(Command::ReadWrite, self.addr, &w_buffers, &mut r_buffers)?;

        for req in requests {
            if req.ensure().is_ok() {
                self.client
                    .notif_handles
                    .lock()
                    .expect("notification handle cache lock poisoned")
                    .remove(&(self.addr, req.req.get()));
            }
        }

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
    Invalid = 0,
    Idle = 1,
    Reset = 2,
    Init = 3,
    Start = 4,
    Run = 5,
    Stop = 6,
    SaveCfg = 7,
    LoadCfg = 8,
    PowerFail = 9,
    PowerGood = 10,
    Error = 11,
    Shutdown = 12,
    Suspend = 13,
    Resume = 14,
    Config = 15,
    Reconfig = 16,
    Stopping = 17,
    Incompatible = 18,
    Exception = 19,
}

impl TryFrom<u16> for AdsState {
    type Error = &'static str;

    fn try_from(value: u16) -> std::result::Result<Self, &'static str> {
        Ok(match value {
            0 => Self::Invalid,
            1 => Self::Idle,
            2 => Self::Reset,
            3 => Self::Init,
            4 => Self::Start,
            5 => Self::Run,
            6 => Self::Stop,
            7 => Self::SaveCfg,
            8 => Self::LoadCfg,
            9 => Self::PowerFail,
            10 => Self::PowerGood,
            11 => Self::Error,
            12 => Self::Shutdown,
            13 => Self::Suspend,
            14 => Self::Resume,
            15 => Self::Config,
            16 => Self::Reconfig,
            17 => Self::Stopping,
            18 => Self::Incompatible,
            19 => Self::Exception,
            _ => return Err("invalid state constant"),
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
            "stopping" => Self::Stopping,
            "incompatible" => Self::Incompatible,
            "exception" => Self::Exception,
            _ => return Err("invalid state name"),
        })
    }
}

// Structures used in communication, not exposed to user,
// but pub(crate) for the test suite.

#[derive(FromBytes, IntoBytes, Immutable, Debug, Clone)]
#[repr(C)]
pub(crate) struct AdsHeader {
    /// 0x0 - ADS command
    /// 0x1 - close port
    /// 0x1000 - open port
    /// 0x1001 - note from router (router state changed)
    /// 0x1002 - get local netid
    pub ams_cmd: u16,
    pub length: U32,
    pub dest_netid: AmsNetId,
    pub dest_port: U16,
    pub src_netid: AmsNetId,
    pub src_port: U16,
    pub command: U16,
    /// 0x01 - response
    /// 0x02 - no return
    /// 0x04 - ADS command
    /// 0x08 - system command
    /// 0x10 - high priority
    /// 0x20 - with time stamp (8 bytes added)
    /// 0x40 - UDP
    /// 0x80 - command during init phase
    /// 0x8000 - broadcast
    pub state_flags: U16,
    pub data_length: U32,
    pub error_code: U32,
    pub invoke_id: U32,
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct DeviceInfoRaw {
    pub major: u8,
    pub minor: u8,
    pub version: U16,
    pub name: [u8; 16],
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct IndexLength {
    pub index_group: U32,
    pub index_offset: U32,
    pub length: U32,
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct ResultLength {
    pub result: U32,
    pub length: U32,
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct IndexLengthRW {
    pub index_group: U32,
    pub index_offset: U32,
    pub read_length: U32,
    pub write_length: U32,
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct ReadState {
    pub ads_state: U16,
    pub dev_state: U16,
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct WriteControl {
    pub ads_state: U16,
    pub dev_state: U16,
    pub data_length: U32,
}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct AddNotif {
    pub index_group: U32,
    pub index_offset: U32,
    pub length: U32,
    pub trans_mode: U32,
    pub max_delay: U32,
    pub cycle_time: U32,
    pub reserved: [u8; 16],
}

/// A single request for a [`Device::read_multi`] request.
pub struct ReadRequest<'buf> {
    req: IndexLength,
    res: ResultLength,
    rbuf: &'buf mut [u8],
}

impl<'buf> ReadRequest<'buf> {
    /// Create the request with given index group, index offset and result buffer.
    pub fn new(index_group: u32, index_offset: u32, buffer: &'buf mut [u8]) -> Self {
        Self {
            req: IndexLength {
                index_group: U32::new(index_group),
                index_offset: U32::new(index_offset),
                length: U32::new(buffer.len() as u32),
            },
            res: ResultLength::new_zeroed(),
            rbuf: buffer,
        }
    }

    /// Get the actual returned data.
    ///
    /// If the request returned an error, returns Err.
    pub fn data(&self) -> Result<&[u8]> {
        if self.res.result.get() != 0 {
            ads_error("multi-read data", self.res.result.get())
        } else {
            Ok(&self.rbuf[..self.res.length.get() as usize])
        }
    }
}

/// A single request for a [`Device::write_multi`] request.
pub struct WriteRequest<'buf> {
    req: IndexLength,
    res: U32,
    wbuf: &'buf [u8],
}

impl<'buf> WriteRequest<'buf> {
    /// Create the request with given index group, index offset and input buffer.
    pub fn new(index_group: u32, index_offset: u32, buffer: &'buf [u8]) -> Self {
        Self {
            req: IndexLength {
                index_group: U32::new(index_group),
                index_offset: U32::new(index_offset),
                length: U32::new(buffer.len() as u32),
            },
            res: U32::default(),
            wbuf: buffer,
        }
    }

    /// Verify that the data was successfully written.
    ///
    /// If the request returned an error, returns Err.
    pub fn ensure(&self) -> Result<()> {
        if self.res.get() != 0 {
            ads_error("multi-write data", self.res.get())
        } else {
            Ok(())
        }
    }
}

/// A single request for a [`Device::write_read_multi`] request.
pub struct WriteReadRequest<'buf> {
    req: IndexLengthRW,
    res: ResultLength,
    wbuf: &'buf [u8],
    rbuf: &'buf mut [u8],
}

impl<'buf> WriteReadRequest<'buf> {
    /// Create the request with given index group, index offset and input and
    /// result buffers.
    pub fn new(
        index_group: u32, index_offset: u32, write_buffer: &'buf [u8], read_buffer: &'buf mut [u8],
    ) -> Self {
        Self {
            req: IndexLengthRW {
                index_group: U32::new(index_group),
                index_offset: U32::new(index_offset),
                read_length: U32::new(read_buffer.len() as u32),
                write_length: U32::new(write_buffer.len() as u32),
            },
            res: ResultLength::new_zeroed(),
            wbuf: write_buffer,
            rbuf: read_buffer,
        }
    }

    /// Get the actual returned data.
    ///
    /// If the request returned an error, returns Err.
    pub fn data(&self) -> Result<&[u8]> {
        if self.res.result.get() != 0 {
            ads_error("multi-read/write data", self.res.result.get())
        } else {
            Ok(&self.rbuf[..self.res.length.get() as usize])
        }
    }
}

/// A single request for a [`Device::add_notification_multi`] request.
pub struct AddNotifRequest {
    req: AddNotif,
    res: ResultLength, // length is the handle
}

impl AddNotifRequest {
    /// Create the request with given index group, index offset and notification
    /// attributes.
    pub fn new(index_group: u32, index_offset: u32, attributes: &notif::Attributes) -> Self {
        Self {
            req: AddNotif {
                index_group: U32::new(index_group),
                index_offset: U32::new(index_offset),
                length: U32::new(attributes.length as u32),
                trans_mode: U32::new(attributes.trans_mode as u32),
                max_delay: U32::new(attributes.max_delay.as_millis() as u32),
                cycle_time: U32::new(attributes.cycle_time.as_millis() as u32),
                reserved: [0; 16],
            },
            res: ResultLength::new_zeroed(),
        }
    }

    /// Get the returned notification handle.
    ///
    /// If the request returned an error, returns Err.
    pub fn handle(&self) -> Result<notif::Handle> {
        if self.res.result.get() != 0 {
            ads_error("multi-read/write data", self.res.result.get())
        } else {
            Ok(self.res.length.get())
        }
    }
}

/// A single request for a [`Device::delete_notification_multi`] request.
pub struct DelNotifRequest {
    req: U32,
    res: U32,
}

impl DelNotifRequest {
    /// Create the request with given index group, index offset and notification
    /// attributes.
    pub fn new(handle: notif::Handle) -> Self {
        Self { req: U32::new(handle), res: U32::default() }
    }

    /// Verify that the handle was successfully deleted.
    ///
    /// If the request returned an error, returns Err.
    pub fn ensure(&self) -> Result<()> {
        if self.res.get() != 0 {
            ads_error("multi-read/write data", self.res.get())
        } else {
            Ok(())
        }
    }
}

fn fixup_write_read_return_buffers(requests: &mut [WriteReadRequest]) {
    // Calculate the initial (using buffer sizes) and actual (using result
    // sizes) offsets of each request.
    let offsets = requests
        .iter()
        .scan((0, 0), |(init_cum, act_cum), req| {
            let (init, act) = (req.rbuf.len(), req.res.length.get() as usize);
            let current = Some((*init_cum, *act_cum, init, act));
            assert!(init >= act);
            *init_cum += init;
            *act_cum += act;
            current
        })
        .collect_vec();

    // Go through the buffers in reverse order.
    for i in (0..requests.len()).rev() {
        let (my_initial, my_actual, _, mut size) = offsets[i];
        if size == 0 {
            continue;
        }
        if my_initial == my_actual {
            // Offsets match, no further action required since all
            // previous buffers must be of full length too.
            break;
        }

        // Check in which buffer our last byte is.
        let mut j = offsets[..i + 1]
            .iter()
            .rposition(|r| r.0 < my_actual + size)
            .expect("index must be somewhere");
        let mut j_end = my_actual + size - offsets[j].0;

        // Copy the required number of bytes from every buffer from j up to i.
        loop {
            let n = j_end.min(size);
            size -= n;
            if i == j {
                requests[i].rbuf.copy_within(j_end - n..j_end, size);
            } else {
                let (first, second) = requests.split_at_mut(i);
                second[0].rbuf[size..][..n].copy_from_slice(&first[j].rbuf[j_end - n..j_end]);
            }
            if size == 0 {
                break;
            }
            j -= 1;
            j_end = offsets[j].2;
        }
    }
}

#[test]
fn test_fixup_buffers() {
    let mut buf0 = *b"12345678AB";
    let mut buf1 = *b"CDEFabc";
    let mut buf2 = *b"dxyUVW";
    let mut buf3 = *b"XYZY";
    let mut buf4 = *b"XW----";
    let mut buf5 = *b"-------------";
    let reqs = &mut [
        WriteReadRequest::new(0, 0, &[], &mut buf0),
        WriteReadRequest::new(0, 0, &[], &mut buf1),
        WriteReadRequest::new(0, 0, &[], &mut buf2),
        WriteReadRequest::new(0, 0, &[], &mut buf3),
        WriteReadRequest::new(0, 0, &[], &mut buf4),
        WriteReadRequest::new(0, 0, &[], &mut buf5),
    ];
    reqs[0].res.length.set(8);
    reqs[1].res.length.set(6);
    reqs[2].res.length.set(0);
    reqs[3].res.length.set(4);
    reqs[4].res.length.set(2);
    reqs[5].res.length.set(9);

    fixup_write_read_return_buffers(reqs);

    assert!(&reqs[5].rbuf[..9] == b"UVWXYZYXW");
    assert!(&reqs[4].rbuf[..2] == b"xy");
    assert!(&reqs[3].rbuf[..4] == b"abcd");
    assert!(&reqs[1].rbuf[..6] == b"ABCDEF");
    assert!(&reqs[0].rbuf[..8] == b"12345678");
}
