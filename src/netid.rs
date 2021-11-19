//! Contains the AMS NetId and related types.

use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::fmt::{self, Display};
use std::io::{Read, Write};

use byteorder::{LE, ReadBytesExt, WriteBytesExt};
use itertools::Itertools;

/// Represents an AMS NetID.
///
/// The NetID consists of 6 bytes commonly written like an IPv4 address, i.e.
/// `1.2.3.4.5.6`. Together with an AMS port (16-bit integer), it uniquely
/// identifies an endpoint of an ADS system that can be communicated with.
///
/// Although often the first 4 bytes of a NetID look like an IP address, and
/// sometimes even are identical to the device's IP address, there is no
/// requirement for this, and one should never rely on it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
pub struct AmsNetId(pub [u8; 6]);

/// An AMS port is, similar to an IP port, a 16-bit integer.
pub type AmsPort = u16;

impl AmsNetId {
    /// Create a NetID from six bytes.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        AmsNetId([a, b, c, d, e, f])
    }

    /// Create a NetID from a slice (which must have length 6).
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        Some(AmsNetId(slice.try_into().ok()?))
    }

    /// Create a NetID from an IPv4 address and two additional octets.
    pub fn from_ip(ip: Ipv4Addr, e: u8, f: u8) -> Self {
        let [a, b, c, d] = ip.octets();
        Self::new(a, b, c, d, e, f)
    }

    /// Check if the NetID is all-zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0, 0, 0]
    }
}

impl FromStr for AmsNetId {
    type Err = &'static str;

    /// Parse a NetID from a string (`a.b.c.d.e.f`).
    ///
    /// Bytes can be missing in the end; missing bytes are substituted by 1.
    fn from_str(s: &str) -> Result<AmsNetId, &'static str> {
        let mut arr = [1; 6];
        for (i, part) in s.split('.').enumerate() {
            match (arr.get_mut(i), part.parse()) {
                (Some(loc), Ok(byte)) => *loc = byte,
                _ => return Err("invalid NetID string"),
            }
        }
        Ok(AmsNetId(arr))
    }
}

impl From<[u8; 6]> for AmsNetId {
    fn from(array: [u8; 6]) -> Self {
        Self(array)
    }
}

impl Display for AmsNetId {
    /// Format a NetID in the usual format.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.iter().format("."))
    }
}

/// Combination of an AMS NetID and a port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct AmsAddr(AmsNetId, AmsPort);

impl AmsAddr {
    pub fn new(netid: AmsNetId, port: AmsPort) -> Self {
        Self(netid, port)
    }

    pub fn netid(&self) -> AmsNetId {
        self.0
    }

    pub fn port(&self) -> AmsPort {
        self.1
    }

    pub fn set_port(&mut self, port: AmsPort) {
        self.1 = port;
    }

    /// Write the NetID to a stream.
    pub fn write_to<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&(self.0).0)?;
        w.write_u16::<LE>(self.1)
    }

    /// Read the NetID from a stream.
    pub fn read_from<R: Read>(r: &mut R) -> std::io::Result<Self> {
        let mut netid = [0; 6];
        r.read_exact(&mut netid)?;
        let port = r.read_u16::<LE>()?;
        Ok(Self(AmsNetId(netid), port))
    }
}

impl FromStr for AmsAddr {
    type Err = &'static str;

    /// Parse an AMS address from a string (netid:port).
    fn from_str(s: &str) -> Result<AmsAddr, &'static str> {
        let (addr, port) = s.split(':').collect_tuple()
                                       .ok_or("invalid AMS addr string")?;
        Ok(Self(addr.parse()?, port.parse().map_err(|_| "invalid port number")?))
    }
}

impl Display for AmsAddr {
    /// Format an AMS address in the usual format.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}
