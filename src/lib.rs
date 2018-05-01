//! Types and utilities to work with PLCs using the ADS protocol
//!
//! # Introduction
//!
//! ADS is the native protocol used by programmable logic controllers (PLCs) and
//! the TwinCAT automation system produced by [Beckhoff
//! GmbH](https://www.beckhoff.com/),
//!
//! The [specification](https://infosys.beckhoff.de/content/1031/tc3_adscommon/html/tcadscommon_introads.htm)
//! can be found on their Information System pages.
//!
//! # Status
//!
//! At present, this is a mere shell containing the most basic things.

extern crate byteorder;
extern crate itertools;

use std::str::FromStr;
use std::fmt::{self, Display};
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
// Instead, the mapping from logical NetIDs to IP addresses to communicate with
// is done by an ADS router, which exists on every TwinCAT system. Since all
// communications is handled by the router, only one TCP/ADS connection exists
// between two hosts. Non-TwinCAT clients should make sure to replicate this
// behavior, as opening a second connection will close the first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AmsNetId(pub [u8; 6]);

/// An AMS port is, similar to an IP port, a 16-bit integer.
pub type AmsPort = u16;

impl AmsNetId {
    /// Create a NetID from six bytes.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        AmsNetId([a, b, c, d, e, f])
    }

    /// Create a NetID from a slice (which must have length 6).
    pub fn from_slice(slice: &[u8]) -> Self {
        debug_assert!(slice.len() == 6);
        let mut arr = [0; 6];
        arr.copy_from_slice(slice);
        AmsNetId(arr)
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

impl Display for AmsNetId {
    /// Format a NetID in the usual format.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.iter().format("."))
    }
}
