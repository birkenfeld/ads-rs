//! File access over ADS.

use std::io;

use crate::index;
use crate::{Device, Error, Result};

/// A file opened within the PLC.  Files implement `Read` and `Write`, so they
/// can be used like normal files in Rust APIs.
///
/// The file is closed automatically on drop.
pub struct File<'c> {
    device: Device<'c>,
    handle: u32,
}

impl<'c> File<'c> {
    /// Open a file.  `flags` must be combined from the constants in this module.
    pub fn open(device: Device<'c>, filename: impl AsRef<[u8]>, flags: u32) -> Result<Self> {
        let mut hdl = [0; 4];
        device.write_read(index::FILE_OPEN, flags, filename.as_ref(), &mut hdl)?;
        Ok(File {
            device,
            handle: u32::from_le_bytes(hdl),
        })
    }

    /// Delete a file.  `flags` must be combined from the constants in this module.
    pub fn delete(device: Device, filename: impl AsRef<[u8]>, flags: u32) -> Result<()> {
        device.write_read(index::FILE_DELETE, flags, filename.as_ref(), &mut []).map(drop)
    }
}

impl<'a> io::Write for File<'a> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.device.write_read(index::FILE_WRITE, self.handle, data, &mut [])
                   // need to convert errors back to io::Error
                   .map_err(map_error)
                   // no info about written length is returned
                   .map(|_| data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> std::io::Read for File<'a> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.device.write_read(index::FILE_READ, self.handle, &[], data).map_err(map_error)
    }
}

impl<'a> Drop for File<'a> {
    fn drop(&mut self) {
        let _ = self.device.write_read(index::FILE_CLOSE, self.handle, &[], &mut []);
    }
}

// Map an ads::Error to an io::Error, trying to keep semantics where possible
fn map_error(e: Error) -> io::Error {
    match e {
        Error::Io(_, io_error) => io_error,
        Error::Ads(_, _, 0x704) => io::ErrorKind::InvalidInput.into(),
        Error::Ads(_, _, 0x70C) => io::ErrorKind::NotFound.into(),
        _ => io::Error::new(io::ErrorKind::Other, e.to_string()),
    }
}

/// File read mode.
pub const READ: u32 = 1 << 0;
/// File write mode.
pub const WRITE: u32 = 1 << 1;
/// File append mode.
pub const APPEND: u32 = 1 << 2;
/// Unknown.
pub const PLUS: u32 = 1 << 3;
/// Binary file mode.
pub const BINARY: u32 = 1 << 4;
/// Text file mode.
pub const TEXT: u32 = 1 << 5;
/// Unknown.
pub const ENSURE_DIR: u32 = 1 << 6;
/// Unknown.
pub const ENABLE_DIR: u32 = 1 << 7;
/// Unknown.
pub const OVERWRITE: u32 = 1 << 8;
/// Unknown.
pub const OVERWRITE_RENAME: u32 = 1 << 9;
