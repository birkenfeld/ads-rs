// Code used in the crate test suite.

use std::convert::TryFrom;
use std::io::{Read, Write};
use std::mem::size_of;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use byteorder::{ReadBytesExt, WriteBytesExt};
use once_cell::sync::Lazy;
use zerocopy::{FromBytes, AsBytes, byteorder::{U16, U32, LE}};

use crate::tcp;

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
                data: vec![0; 1024],
                state: (tcp::AdsState::Run, 0)
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
    pub garbage_header: bool,
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

            let (reply_data, error) = match header.cmd.get() {
                1 => self.do_devinfo(&data),
                2 => self.do_read(&data),
                3 => self.do_write(&data),
                4 => self.do_read_state(&data),
                5 => self.do_write_control(&data),
                // 6 => self.do_add_notif(&data),
                // 7 => self.do_del_notif(&data),
                // 9 => self.do_read_write(&data),
                _ => (vec![], 0x701),
            };

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
            reply_header.inv_id = header.inv_id;
            println!("rep: {:?}", reply_header);

            socket.write_all(reply_header.as_bytes()).unwrap();
            socket.write_all(&reply_data).unwrap();
        }
    }

    fn do_devinfo(&self, data: &[u8]) -> (Vec<u8>, u32) {
        if !data.is_empty() {
            return (vec![], 0x706);
        }
        // no error, major 7, minor 1
        let mut out = vec![0, 0, 0, 0, 7, 1];
        out.write_u16::<LE>(4024).unwrap();
        out.extend(b"Nice device\0\0\0\0\0");
        (out, 0)
    }

    fn do_read_state(&self, data: &[u8]) -> (Vec<u8>, u32) {
        if !data.is_empty() {
            return (vec![], 0x706);
        }
        let mut out = vec![0, 0, 0, 0];
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
        if request.igrp.get() != 0x4020 {
            return (vec![], 0x702);
        }
        let off = request.ioff.get() as usize;
        let len = request.len.get() as usize;
        if off + len >= self.data.len() {
            return (vec![], 0x703);
        }
        let mut ret = Vec::new();
        ret.write_u32::<LE>(0).unwrap();
        ret.write_u32::<LE>(request.len.get()).unwrap();
        ret.extend(&self.data[off..][..len]);
        (ret, 0)
    }

    fn do_write(&mut self, data: &[u8]) -> (Vec<u8>, u32) {
        if data.len() < size_of::<IndexLen>() {
            return (vec![], 0x706);
        }
        let request = IndexLen::read_from(&data[..12]).unwrap();
        if request.igrp.get() != 0x4020 {
            return (vec![], 0x702);
        }
        let off = request.ioff.get() as usize;
        let len = request.len.get() as usize;
        if off + len >= self.data.len() {
            return (vec![], 0x703);
        }
        if data.len() != size_of::<IndexLen>() + len {
            return (vec![], 0x706);
        }
        self.data[off..][..len].copy_from_slice(&data[12..]);
        (vec![0, 0, 0, 0], 0)
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
