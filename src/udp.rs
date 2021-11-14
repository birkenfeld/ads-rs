//! Implements the Beckhoff UDP message protocol for basic operations.

use std::io::Write;
use std::net::UdpSocket;
use std::str;

use byteorder::{LE, ReadBytesExt, WriteBytesExt, ByteOrder};

use crate::{AmsAddr, Error, Result};

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
    Version = 3,
    ComputerName = 5,
    NetID = 7,
    Options = 9,
    RouteName = 12,
    UserName = 13,
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
    pub fn send_receive(&self, dest: &str) -> Result<UdpMessage> {
        // Send self as a request.
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        sock.send_to(self.as_bytes(), format!("{}:{}", dest, crate::ADS_UDP_PORT))?;

        // Receive the reply.
        let mut reply = [0; 576];
        sock.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
        let (n, _) = sock.recv_from(&mut reply)?;

        // Parse the reply.
        Self::parse_reply(&reply[..n], self.service)
    }
}
