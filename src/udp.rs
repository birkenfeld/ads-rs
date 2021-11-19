//! Implements the Beckhoff UDP message protocol for basic operations.

use std::convert::TryInto;
use std::io::Write;
use std::net::{ToSocketAddrs, UdpSocket};
use std::str;

use byteorder::{LE, ReadBytesExt, WriteBytesExt, ByteOrder};

use crate::{AmsAddr, AmsNetId, Error, Result};

/// Magic number for the first four bytes of each UDP packet.
pub const BECKHOFF_UDP_MAGIC: u32 = 0x_71_14_66_03;

/// Represents a message in the UDP protocol.
pub struct UdpMessage {
    service: u32,
    items: Vec<(u16, usize, usize)>,
    data: Vec<u8>,
}

/// The operation that the PLC should execute.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum ServiceId {
    Identify = 1,
    AddRoute = 6,
}

/// Identifies a piece of information in the UDP message.
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum Tag {
    Status = 1,
    Password = 2,
    TCVersion = 3,
    OSVersion = 4,
    ComputerName = 5,
    NetID = 7,
    Options = 9,
    RouteName = 12,
    UserName = 13,
    // ? = 18  sent in reply to Identify, could be an SHA-256
}

impl UdpMessage {
    /// Create a new UDP message backed by a byte vector.
    pub fn new(service: ServiceId, source: AmsAddr) -> UdpMessage {
        let mut data = Vec::with_capacity(100);
        for &n in &[BECKHOFF_UDP_MAGIC, 0, service as u32] {
            data.write_u32::<LE>(n).unwrap();
        }
        source.write_to(&mut data).unwrap();
        data.write_u32::<LE>(0).unwrap();  // number of items, will be increased later
        UdpMessage { service: service as u32, items: Vec::with_capacity(8), data }
    }

    /// Add a tag containing arbitrary bytes.
    pub fn add_bytes(&mut self, tag: Tag, data: &[u8]) {
        self.data.write_u16::<LE>(tag as u16).unwrap();
        let start = self.data.len();
        self.data.write_u16::<LE>(data.len() as u16).unwrap();
        self.data.write_all(data).unwrap();
        self.items.push((tag as u16, start, self.data.len()));
        LE::write_u32(&mut self.data[20..], self.items.len() as u32);
    }

    /// Add a tag containing a string with null terminator.
    pub fn add_str(&mut self, tag: Tag, data: &str) {
        self.data.write_u16::<LE>(tag as u16).unwrap();
        let start = self.data.len();
        self.data.write_u16::<LE>(data.len() as u16 + 1).unwrap();
        self.data.write_all(data.as_bytes()).unwrap();
        self.data.write_u8(0).unwrap();
        self.items.push((tag as u16, start, self.data.len()));
        LE::write_u32(&mut self.data[20..], self.items.len() as u32);
    }

    /// Add a tag containing an u32.
    pub fn add_u32(&mut self, tag: Tag, data: u32) {
        self.data.write_u16::<LE>(tag as u16).unwrap();
        let start = self.data.len();
        self.data.write_u16::<LE>(4).unwrap();
        self.data.write_u32::<LE>(data).unwrap();
        self.items.push((tag as u16, start, self.data.len()));
        LE::write_u32(&mut self.data[20..], self.items.len() as u32);
    }

    /// Parse a UDP message from a byte slice.
    pub fn parse_reply(data: &[u8], service: u32) -> Result<Self> {
        let mut data_ptr = data;
        if data_ptr.read_u32::<LE>()? != BECKHOFF_UDP_MAGIC {
            return Err(Error::Udp("magic not recognized"));
        }
        if data_ptr.read_u32::<LE>()? != 0 {  // we're only generating 0
            return Err(Error::Udp("invalid invoke ID"));
        }
        if data_ptr.read_u32::<LE>()? != service | 0x8000_0000 {
            return Err(Error::Udp("operation acknowledge missing"));
        }
        let _src = AmsAddr::read_from(&mut data_ptr)?;
        let nitems = data_ptr.read_u32::<LE>()?;

        let mut items = Vec::with_capacity(nitems as usize);
        {
            let mut pos = 28;
            while let Ok(tag) = data_ptr.read_u16::<LE>() {
                let len = data_ptr.read_u16::<LE>()? as usize;
                items.push((tag, pos, pos + len));
                pos += len + 4;
                data_ptr = &data_ptr[len..];
            }
        }
        Ok(UdpMessage { service, data: data.to_vec(), items })
    }

    fn map_tag<'a, O, F>(&'a self, tag: Tag, map: F) -> Option<O>
        where F: Fn(&'a [u8]) -> Option<O>
    {
        self.items.iter().find(|item| item.0 == tag as u16)
                         .and_then(|&(_, i, j)| map(&self.data[i..j]))
    }

    /// Get the data for given tag as bytes.
    pub fn get_bytes(&self, tag: Tag) -> Option<&[u8]> {
        self.map_tag(tag, Some)
    }

    /// Get the data for given tag as null-terminated string.
    pub fn get_str(&self, tag: Tag) -> Option<&str> {
        self.map_tag(tag, |b| str::from_utf8(b).ok())
    }

    /// Get the data for given tag as a u32.
    pub fn get_u32(&self, tag: Tag) -> Option<u32> {
        self.map_tag(tag, |mut b| b.read_u32::<LE>().ok())
    }

    /// Get the AMS address originating the message.
    pub fn get_source(&self) -> AmsAddr {
        AmsAddr::read_from(&mut &self.data[12..20]).unwrap()
    }

    /// Create a complete UDP packet from the message and its header.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Send the packet and receive a reply from the server.
    pub fn send_receive(&self, to: impl ToSocketAddrs) -> Result<UdpMessage> {
        // Send self as a request.
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.send_to(self.as_bytes(), to)?;

        // Receive the reply.
        let mut reply = [0; 576];
        sock.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
        let (n, _) = sock.recv_from(&mut reply)?;

        // Parse the reply.
        Self::parse_reply(&reply[..n], self.service)
    }
}

/// Send a UDP message for setting a route.
///
/// - `target`: (host, port) of the AMS router to add the route to
///   (the port should normally be `ads::ADS_UDP_PORT`)
/// - `netid`: the NetID of the route's target
/// - `host`: the IP address or hostname of the route's target (when using
///   hostnames instead of IP addresses, beware of Windows hostname resolution)
/// - `routename`: name of the route, default is `host`
/// - `username`: system username for the router, default is `Administrator`
/// - `password`: system password for the given user, default is `1`
/// - `temporary`: marks the route as "temporary"
pub fn add_route(target: (&str, u16), netid: AmsNetId, host: &str,
                 routename: Option<&str>, username: Option<&str>,
                 password: Option<&str>, temporary: bool) -> Result<()> {
    let mut packet = UdpMessage::new(ServiceId::AddRoute, AmsAddr::new(netid, 0));
    packet.add_bytes(Tag::NetID, &netid.0);
    packet.add_str(Tag::ComputerName, host);
    packet.add_str(Tag::UserName, username.unwrap_or("Administrator"));
    packet.add_str(Tag::Password, password.unwrap_or("1"));
    packet.add_str(Tag::RouteName, routename.unwrap_or(host));
    if temporary {
        packet.add_u32(Tag::Options, 1);
    }

    let reply = packet.send_receive(target)?;

    match reply.get_u32(Tag::Status) {
        None => Err(Error::Udp("got no status in route reply")),
        Some(0) => Ok(()),
        Some(n) => crate::errors::ads_error(n),
    }
}

pub struct SysInfo {
    pub netid: AmsNetId,
    pub hostname: String,
    pub twincat_version: (u8, u8, u16),
    pub os_version: (&'static str, u32, u32, u32, String),
}

/// Send a UDP message for querying remote system NetID.
pub fn get_netid(target: (&str, u16)) -> Result<AmsNetId> {
    let packet = UdpMessage::new(ServiceId::Identify, AmsAddr::default());
    let reply = packet.send_receive(target)?;
    Ok(reply.get_source().netid())
}

/// Send a UDP message for querying remote system information.
pub fn get_info(target: (&str, u16)) -> Result<SysInfo> {
    let packet = UdpMessage::new(ServiceId::Identify, AmsAddr::default());
    let reply = packet.send_receive(target)?;
    let tcver = reply.get_bytes(Tag::TCVersion).unwrap_or(&[0, 0, 0, 0]);
    let twincat_version = (tcver[0], tcver[1], u16::from_le_bytes(tcver[2..4].try_into().unwrap()));
    let os_version = if let Some(mut bytes) = reply.get_bytes(Tag::OSVersion) {
        if bytes.len() >= 22 {
            let _ = bytes.read_u32::<LE>().unwrap();
            let major = bytes.read_u32::<LE>().unwrap();
            let minor = bytes.read_u32::<LE>().unwrap();
            let build = bytes.read_u32::<LE>().unwrap();
            let platform = match bytes.read_u32::<LE>().unwrap() {
                1 => "Windows 9x",
                2 => "Windows NT",
                3 => "Windows CE",
                _ => "Unknown platform",
            };
            let mut string = String::new();
            while let Ok(ch) = bytes.read_u16::<LE>() {
                string.push(std::char::from_u32(ch as u32).unwrap());
                if ch == 0 {
                    break;
                }
            }
            (platform, major, minor, build, string)
        } else {
            ("Unknown OS info format", 0, 0, 0, "".into())
        }
    } else {
        ("No OS info", 0, 0, 0, "".into())
    };
    Ok(SysInfo {
        netid: reply.get_source().netid(),
        hostname: reply.get_str(Tag::ComputerName).unwrap_or("unknown").into(),
        twincat_version,
        os_version,
    })
}
