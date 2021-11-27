//! Wrappers for symbol operations and symbol handles.

use std::convert::TryInto;

use crate::index;
use crate::{Device, Result};

/// A handle to a variable within the ADS device.
///
/// The handle is released automatically on drop.
pub struct Handle<'c> {
    device: Device<'c>,
    handle: u32,
}

impl<'c> Handle<'c> {
    /// Create a new handle to a single symbol.
    pub fn new(device: Device<'c>, symbol: &str) -> Result<Self> {
        let mut handle_bytes = [0; 4];
        device.write_read_exact(index::GET_SYMHANDLE_BYNAME, 0, symbol.as_bytes(),
                                &mut handle_bytes)?;
        Ok(Self { device, handle: u32::from_le_bytes(handle_bytes) })
    }

    /// Read data from the variable (returned data must match size of buffer).
    pub fn read(&self, buf: &mut [u8]) -> Result<()> {
        self.device.read_exact(index::RW_SYMVAL_BYHANDLE, self.handle, buf)
    }

    /// Write data to the variable.
    pub fn write(&self, buf: &[u8]) -> Result<()> {
        self.device.write(index::RW_SYMVAL_BYHANDLE, self.handle, buf)
    }
}

impl<'a> Drop for Handle<'a> {
    fn drop(&mut self) {
        let _ = self.device.write(index::RELEASE_SYMHANDLE, 0,
                                  &self.handle.to_le_bytes());
    }
}

/// Get symbol size by name.
pub fn get_size(device: Device<'_>, symbol: &str) -> Result<usize> {
    let mut buf = [0; 12];
    device.write_read_exact(index::GET_SYMINFO_BYNAME, 0, symbol.as_bytes(), &mut buf)?;
    Ok(u32::from_le_bytes(buf[8..].try_into().expect("size")) as usize)
}

/// Get symbol location (index group and index offset) by name.
pub fn get_location(device: Device<'_>, symbol: &str) -> Result<(u32, u32)> {
    let mut buf = [0; 12];
    device.write_read_exact(index::GET_SYMINFO_BYNAME, 0, symbol.as_bytes(), &mut buf)?;
    Ok((u32::from_le_bytes(buf[0..4].try_into().expect("size")),
        u32::from_le_bytes(buf[4..8].try_into().expect("size"))))
}
