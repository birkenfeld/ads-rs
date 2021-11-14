//! File access over ADS.

use std::io;

use crate::{Device, Error, Result};
use crate::index;

pub struct File<'a> {
    device: &'a mut Device,
    handle: u32,
}

impl<'a> File<'a> {
    pub fn delete(device: &mut Device, filename: impl AsRef<[u8]>, flags: u32) -> Result<()> {
        device.write_read(index::SYS_FILE_DELETE, flags, filename.as_ref(), &mut []).map(drop)
    }

    pub fn open(device: &'a mut Device, filename: impl AsRef<[u8]>, flags: u32) -> Result<Self> {
        let mut hdl = [0; 4];
        device.write_read(index::SYS_FILE_OPEN, flags, filename.as_ref(), &mut hdl)?;
        Ok(File {
            device,
            handle: u32::from_le_bytes(hdl)
        })
    }
}

impl<'a> io::Write for File<'a> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.device.write_read(index::SYS_FILE_WRITE, self.handle, data, &mut [])
                   .map_err(|e| match e {
                       Error::Io(ioe) => ioe,
                       _ => io::Error::new(io::ErrorKind::Other, e.to_string())
                   })
                   .map(|_| data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> std::io::Read for File<'a> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.device.write_read(index::SYS_FILE_READ, self.handle, &[], data)
                   .map_err(|e| match e {
                       Error::Io(ioe) => ioe,
                       _ => io::Error::new(io::ErrorKind::Other, e.to_string())
                   })
                   .map(|_| data.len())
    }
}

impl<'a> Drop for File<'a> {
    fn drop(&mut self) {
        let _ = self.device.write_read(index::SYS_FILE_CLOSE, self.handle, &[], &mut []);
    }
}

/// File flags

pub const READ: u32 = 1 << 0;
pub const WRITE: u32 = 1 << 1;
pub const APPEND: u32 = 1 << 2;
pub const PLUS: u32 = 1 << 3;
pub const BINARY: u32 = 1 << 4;
pub const TEXT: u32 = 1 << 5;
pub const ENSURE_DIR: u32 = 1 << 6;
pub const ENABLE_DIR: u32 = 1 << 7;
pub const OVERWRITE: u32 = 1 << 8;
pub const OVERWRITE_RENAME: u32 = 1 << 9;
