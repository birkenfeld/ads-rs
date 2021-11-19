//! Work with PLCs using the ADS protocol
//!
//! # Introduction
//!
//! ADS is the native protocol used by programmable logic controllers (PLCs) and
//! the TwinCAT automation system produced by [Beckhoff GmbH](https://www.beckhoff.com/).
//!
//! The [specification](https://infosys.beckhoff.de/content/1031/tc3_adscommon/html/tcadscommon_introads.htm)
//! can be found on their Information System pages.
//!
//! # Example
//!
//! ```rust,ignore
//! // Open the connection to a PLC.
//! let timeouts = ads::Timeouts::new(std::time::Duration::from_secs(1));
//! let client = ads::Client::new("myplc:48898", timeouts, None)?;
//!
//! // Get a handle for a symbol and read data from it.
//! let handle = client.device
//! ```

#![deny(missing_docs)]

pub mod netid;
pub mod tcp;
pub mod notify;
pub mod udp;
pub mod errors;
pub mod ports;
pub mod index;
pub mod file;
pub mod symbol;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod test_tcp;

pub use netid::{AmsAddr, AmsNetId, AmsPort};
pub use tcp::{Client, Device, Timeouts};
pub use udp::UdpMessage;
pub use errors::{Error, Result};

/// The default port for TCP communication.
pub const ADS_PORT: u16 = 0xBF02;
/// The default port for UDP communication.
pub const ADS_UDP_PORT: u16 = 0xBF03;
