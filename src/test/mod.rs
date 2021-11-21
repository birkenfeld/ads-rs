// Code used in the crate test suite.

use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};
use std::mem::size_of;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use byteorder::{ReadBytesExt, WriteBytesExt};
use once_cell::sync::Lazy;
use zerocopy::{FromBytes, AsBytes, byteorder::{U16, U32, U64, LE}};

use crate::{file, index, tcp};

// Test modules.
mod test_tcp;
mod test_udp;
mod test_netid;


// Since Cargo tests run multi-threaded, start one server per thread and
// handle clients from the test functions in that thread.
thread_local! {
    pub static SERVER: Lazy<(u16, Arc<Mutex<ServerOpts>>)> = Lazy::new(|| {
        let opts = Arc::new(Mutex::new(ServerOpts::default()));

        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let opts_server = opts.clone();
        thread::spawn(move || {
            let mut server = Server {
                opts: opts_server,
                state: (tcp::AdsState::Run, 0),
                data: vec![0; 1024],
                file_ptr: None,
                notif: None,
            };
            for client in socket.incoming().flatten() {
                // We only need to handle one client concurrently.
                server.handle_client(client);
            }
        });

        (port, opts)
    });
}

// Configures different ways the server should behave.
#[derive(Default)]
pub struct ServerOpts {
    pub timeout: Option<Duration>,
    pub no_reply: bool,
    pub garbage_header: bool,
    pub bad_notif: bool,
    pub ignore_invokeid: bool,
}

pub fn config_test_server(opts: ServerOpts) -> u16 {
    SERVER.with(|obj| {
        let (port, server_opts) = &**obj;
        *server_opts.lock().unwrap() = opts;
        *port
    })
}

struct Server {
    opts: Arc<Mutex<ServerOpts>>,
    data: Vec<u8>,
    // If the test file is opened for writing, and the read/write position.
    file_ptr: Option<(bool, usize)>,
    // If a notification has been added, the (offset, size) to send.
    notif: Option<(usize, usize)>,
    // The simulated device state.
    state: (tcp::AdsState, u16),
}

impl Server {
    fn handle_client(&mut self, mut socket: TcpStream) {
        let opts = self.opts.clone();
        loop {
            let opts = opts.lock().unwrap();
            let mut header = AdsHeader::new_zeroed();
            if let Err(e) = socket.read_exact(header.as_bytes_mut()) {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    // connection was closed
                    return;
                }
                panic!("unexpected receive error: {}", e);
            }
            println!("req: {:?}", header);
            let mut data = vec![0; header.data_len.get() as usize];
            socket.read_exact(&mut data).unwrap();

            if opts.no_reply {
                return;
            }

            let (reply_data, error) = match header.cmd.get() {
                1 => self.do_devinfo(&data),
                2 => self.do_read(&data),
                3 => self.do_write(&data),
                4 => self.do_read_state(&data),
                5 => self.do_write_control(&data),
                6 => self.do_add_notif(&data),
                7 => self.do_del_notif(&data),
                9 => self.do_read_write(&data),
                _ => (vec![], 0x701),
            };

            // Generate a notification if they are enabled.
            if let Some((off, len)) = &self.notif {
                self.send_notification(*off, *len, &header, opts.bad_notif, &mut socket);
            }

            let mut reply_header = AdsHeader::new_zeroed();
            if opts.garbage_header {
                reply_header.pad = 234;
            }
            reply_header.len.set(32 + reply_data.len() as u32);
            reply_header.dst_addr = header.src_addr;
            reply_header.dst_port = header.src_port;
            reply_header.src_addr = header.dst_addr;
            reply_header.src_port = header.dst_port;
            reply_header.cmd = header.cmd;
            reply_header.state.set(header.state.get() | 1);
            reply_header.data_len.set(reply_data.len() as u32);
            reply_header.error.set(error);
            if !opts.ignore_invokeid {
                reply_header.inv_id = header.inv_id;
            }
            println!("rep: {:?}", reply_header);

            socket.write_all(reply_header.as_bytes()).unwrap();
            socket.write_all(&reply_data).unwrap();
        }
    }

    fn send_notification(&self, off: usize, len: usize, header: &AdsHeader,
                         bad: bool, socket: &mut TcpStream) {
        let data_len = std::mem::size_of::<NotifHdr>() + len;

        let mut notif_header = NotifHdr::new_zeroed();
        notif_header.len.set(data_len as u32 - 4);
        notif_header.stamps.set(if bad { u32::MAX } else { 1 });
        notif_header.stamp.set(0x9988776655443322);
        notif_header.samples.set(1);
        notif_header.handle.set(132);
        notif_header.size.set(len as u32);

        let mut ads_header = AdsHeader::new_zeroed();
        ads_header.len.set(32 + data_len as u32);
        ads_header.dst_addr = header.src_addr;
        ads_header.dst_port = header.src_port;
        ads_header.src_addr = header.dst_addr;
        ads_header.src_port = header.dst_port;
        ads_header.cmd.set(crate::tcp::Command::Notification as u16);
        ads_header.state.set(4);
        ads_header.data_len.set(data_len as u32);
        println!("not: {:?}", ads_header);

        socket.write_all(ads_header.as_bytes()).unwrap();
        socket.write_all(notif_header.as_bytes()).unwrap();
        socket.write_all(&self.data[off..][..len]).unwrap();
    }

    fn do_devinfo(&self, data: &[u8]) -> (Vec<u8>, u32) {
        if !data.is_empty() {
            return (vec![], 0x706);
        }
        // no error, major 7, minor 1
        let mut out = 0u32.to_le_bytes().to_vec();
        out.write_u8(7).unwrap();
        out.write_u8(1).unwrap();
        out.write_u16::<LE>(4024).unwrap();
        out.extend(b"Nice device\0\0\0\0\0");
        (out, 0)
    }

    fn do_read_state(&self, data: &[u8]) -> (Vec<u8>, u32) {
        if !data.is_empty() {
            return (vec![], 0x706);
        }
        let mut out = 0u32.to_le_bytes().to_vec();
        out.write_u16::<LE>(self.state.0 as u16).unwrap();
        out.write_u16::<LE>(self.state.1).unwrap();
        (out, 0)
    }

    fn do_write_control(&mut self, mut data: &[u8]) -> (Vec<u8>, u32) {
        if data.len() != 8 {
            return (vec![], 0x706);
        }
        let adsstate = data.read_u16::<LE>().unwrap();
        let devstate = data.read_u16::<LE>().unwrap();
        let mut out = vec![];
        match tcp::AdsState::try_from(adsstate) {
            Err(_) | Ok(tcp::AdsState::Invalid) => {
                out.write_u32::<LE>(0x70B).unwrap();
            }
            Ok(adsstate) => {
                self.state = (adsstate, devstate);
                out.write_u32::<LE>(0).unwrap();
            }
        }
        (out, 0)
    }

    fn do_read(&self, data: &[u8]) -> (Vec<u8>, u32) {
        if data.len() != size_of::<IndexLen>() {
            return (vec![], 0x706);
        }
        let request = IndexLen::read_from(data).unwrap();
        let mut off = request.ioff.get() as usize;
        let len = request.len.get() as usize;
        let mut out = Vec::new();
        out.write_u32::<LE>(0).unwrap();
        // Simulate symbol access.
        if request.igrp.get() == index::RW_SYMVAL_BYHANDLE {
            if off != 77 {
                return (vec![], 0x710);
            }
            off = 1020;  // symbol lives at the end of self.data
        } else if request.igrp.get() != index::PLC_RW_M {
            return (vec![], 0x702);
        }
        if off + len > self.data.len() {
            return (vec![], 0x703);
        }
        out.write_u32::<LE>(request.len.get()).unwrap();
        out.extend(&self.data[off..][..len]);
        (out, 0)
    }

    fn do_write(&mut self, data: &[u8]) -> (Vec<u8>, u32) {
        if data.len() < size_of::<IndexLen>() {
            return (vec![], 0x706);
        }
        let request = IndexLen::read_from(&data[..12]).unwrap();
        let mut off = request.ioff.get() as usize;
        let len = request.len.get() as usize;

        if request.igrp.get() == index::RW_SYMVAL_BYHANDLE {
            if off != 77 {
                return (vec![], 0x710);
            }
            off = 1020;
        } else if request.igrp.get() == index::RELEASE_SYMHANDLE {
            if off != 77 {
                return (vec![], 0x710);
            }
            return (0u32.to_le_bytes().into(), 0);
        } else if request.igrp.get() != index::PLC_RW_M {
            return (vec![], 0x702);
        }
        if off + len > self.data.len() {
            return (vec![], 0x703);
        }
        if data.len() != size_of::<IndexLen>() + len {
            return (vec![], 0x706);
        }
        self.data[off..][..len].copy_from_slice(&data[12..]);
        (0u32.to_le_bytes().into(), 0)
    }

    fn do_read_write(&mut self, data: &[u8]) -> (Vec<u8>, u32) {
        if data.len() < size_of::<Index2Len>() {
            return (vec![], 0x706);
        }
        let request = Index2Len::read_from(&data[..16]).unwrap();
        let off = request.ioff.get();
        let rlen = request.rlen.get() as usize;
        let wlen = request.wlen.get() as usize;
        let mut out = 0u32.to_le_bytes().to_vec();

        // Simulate file and symbol access.
        match request.igrp.get() {
            index::FILE_OPEN => {
                if &data[16..] != b"/etc/passwd" {
                    return (vec![], 0x70C);
                }
                if self.file_ptr.is_some() {
                    return (vec![], 0x708);
                }
                let write = off & (file::WRITE | file::APPEND) != 0;
                out.write_u32::<LE>(4).unwrap();
                out.write_u32::<LE>(42).unwrap();
                self.file_ptr = Some((write, 0));
            }
            index::FILE_CLOSE => {
                if !data[16..].is_empty() {
                    return (vec![], 0x70B);
                }
                if off != 42 {
                    return (vec![], 0x70C);
                }
                out.write_i32::<LE>(0).unwrap();
                self.file_ptr = None;
            }
            index::FILE_WRITE => {
                if let Some((true, ptr)) = &mut self.file_ptr {
                    out.write_i32::<LE>(0).unwrap();
                    *ptr += wlen;
                } else {
                    return (vec![], 0x704);
                }
            }
            index::FILE_READ => {
                if let Some((false, ptr)) = &mut self.file_ptr {
                    let cur = *ptr;
                    *ptr = (*ptr + rlen).min(888);
                    let amount = *ptr - cur;
                    out.write_u32::<LE>(amount as u32).unwrap();
                    out.resize(out.len() + amount, 0);
                } else {
                    return (vec![], 0x704);
                }
            }
            index::FILE_DELETE => {
                if &data[16..] != b"/etc/passwd" {
                    return (vec![], 0x70C);
                }
                if self.file_ptr.is_some() {
                    // send an unknown error number
                    return (vec![], 0xFFFF);
                }
                out.write_i32::<LE>(0).unwrap();
            }
            index::GET_SYMHANDLE_BYNAME => {
                if &data[16..] != b"SYMBOL" {
                    return (vec![], 0x710);
                }
                out.write_i32::<LE>(4).unwrap();
                out.write_i32::<LE>(77).unwrap();
            }
            _ => return (vec![], 0x702),
        }
        (out, 0)
    }

    fn do_add_notif(&mut self, data: &[u8]) -> (Vec<u8>, u32) {
        if data.len() != size_of::<AddNotif>() {
            return (vec![], 0x706);
        }
        let request = AddNotif::read_from(data).unwrap();
        let off = request.ioff.get() as usize;
        let len = request.len.get() as usize;

        if request.igrp.get() != index::PLC_RW_M {
            return (vec![], 0x702);
        }
        if off + len > self.data.len() {
            return (vec![], 0x703);
        }
        self.notif = Some((off, len));
        let mut out = 0u32.to_le_bytes().to_vec();
        out.write_u32::<LE>(132).unwrap(); // handle
        (out, 0)
    }

    fn do_del_notif(&mut self, data: &[u8]) -> (Vec<u8>, u32) {
        if data.len() != 4 {
            return (vec![], 0x706);
        }
        let handle = u32::from_le_bytes(data.try_into().unwrap());
        if handle != 132 {
            return (vec![], 0x714);
        }
        if self.notif.is_none() {
            return (vec![], 0x714);
        }
        self.notif = None;
        (0u32.to_le_bytes().into(), 0)
    }
}

#[derive(AsBytes, FromBytes, Debug)]
#[repr(C)]
struct AdsHeader {
    pad:      u16,
    len:      U32<LE>,
    dst_addr: [u8; 6],
    dst_port: U16<LE>,
    src_addr: [u8; 6],
    src_port: U16<LE>,
    cmd:      U16<LE>,
    state:    U16<LE>,
    data_len: U32<LE>,
    error:    U32<LE>,
    inv_id:   U32<LE>,
}

#[derive(AsBytes, FromBytes, Debug)]
#[repr(C)]
struct IndexLen {
    igrp: U32<LE>,
    ioff: U32<LE>,
    len:  U32<LE>,
}

#[derive(AsBytes, FromBytes, Debug)]
#[repr(C)]
struct Index2Len {
    igrp: U32<LE>,
    ioff: U32<LE>,
    rlen: U32<LE>,
    wlen: U32<LE>,
}

#[derive(AsBytes, FromBytes, Debug)]
#[repr(C)]
struct AddNotif {
    igrp:  U32<LE>,
    ioff:  U32<LE>,
    len:   U32<LE>,
    mode:  U32<LE>,
    delay: U32<LE>,
    cycle: U32<LE>,
    resvd: [u8; 16],
}

#[derive(AsBytes, FromBytes, Debug)]
#[repr(C)]
struct NotifHdr {
    len:     U32<LE>,
    stamps:  U32<LE>,
    stamp:   U64<LE>,
    samples: U32<LE>,
    handle:  U32<LE>,
    size:    U32<LE>,
}
