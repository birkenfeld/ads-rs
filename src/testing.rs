// Code used in the crate test suite.

use std::io::{Read, Write};
use std::mem::size_of;
use std::net::{TcpListener, TcpStream};
use std::sync::Once;
use std::thread;

use byteorder::WriteBytesExt;
use zerocopy::{FromBytes, AsBytes, byteorder::{U16, U32, LE}};

static SERVER: Once = Once::new();

pub fn start_test_server() {
    SERVER.call_once(|| {
        let server = TcpListener::bind("127.0.0.1:49000").unwrap();
        thread::spawn(move || {
            for client in server.incoming().flatten() {
                thread::Builder::new()
                    .name("test connection handler".into())
                    .spawn(move || handle_client(client))
                    .unwrap();
            }
        });
    });
}

#[derive(AsBytes, FromBytes, Debug)]
#[repr(C)]
struct AdsHeader {
    pad:         u16,
    length:      U32<LE>,
    dest_addr:   [u8; 6],
    dest_port:   U16<LE>,
    src_addr:    [u8; 6],
    src_port:    U16<LE>,
    cmd:         U16<LE>,
    state:       U16<LE>,
    data_length: U32<LE>,
    error:       U32<LE>,
    invoke_id:   U32<LE>,
}

fn handle_client(mut socket: TcpStream) {
    assert_eq!(size_of::<AdsHeader>(), 38);
    loop {
        let mut header = AdsHeader::new_zeroed();
        socket.read_exact(header.as_bytes_mut()).unwrap();
        dbg!(&header);
        let mut data = vec![0; header.data_length.get() as usize];
        socket.read_exact(&mut data).unwrap();

        let (reply_data, error) = match header.cmd.get() {
            1 => do_devinfo(&data),
            // 2 => do_read(&header, &data),
            // 3 => do_write(&header, &data),
            // 4 => do_read_state(&header, &data),
            // 5 => do_write_control(&header, &data),
            // 6 => do_add_notif(&header, &data),
            // 7 => do_del_notif(&header, &data),
            // 9 => do_read_write(&header, &data),
            _ => (vec![], 0x701),
        };

        let mut reply_header = AdsHeader::new_zeroed();
        reply_header.length.set(32 + reply_data.len() as u32);
        reply_header.dest_addr = header.src_addr;
        reply_header.dest_port = header.src_port;
        reply_header.src_addr = header.dest_addr;
        reply_header.src_port = header.dest_port;
        reply_header.cmd = header.cmd;
        reply_header.state.set(header.state.get() | 1);
        reply_header.data_length.set(reply_data.len() as u32);
        reply_header.error.set(error);
        reply_header.invoke_id = header.invoke_id;
        dbg!(&reply_header);

        socket.write_all(reply_header.as_bytes()).unwrap();
        socket.write_all(&reply_data).unwrap();
    }
}

fn do_devinfo(data: &[u8]) -> (Vec<u8>, u32) {
    if !data.is_empty() {
        return (vec![], 0x706);
    }
    // no error, major 7, minor 1
    let mut out = vec![0, 0, 0, 0, 7, 1];
    out.write_u16::<LE>(4024).unwrap();
    out.extend(b"Nice device\0\0\0\0\0");
    (out, 0)
}
