#![allow(unused)]

use ads::Client;

fn main_dumb() {
    let mut sock = std::net::TcpStream::connect("127.0.0.1:48999").unwrap();
    use std::io::{Write,Read};
    let now = std::time::Instant::now();
    for _ in 0..5000 {
        let mut buf = [0; 50];
        sock.write_all(b"\x00\x00(\x00\x00\x00\x7f\x00\x00\x01\x01\x01\x00\x00\
                         \x01\x02\x03\x04\x05\x06S\x03\x02\x00\x05\x00\x0c\x00\
                         \x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                         \x00\x04\x00\x00\x00\xa4\xe0\xfbD").unwrap();
        sock.read_exact(&mut buf).unwrap();
    }
    println!("dumb:   {:?}", now.elapsed());
}

fn main_client() {
    let timeout = ads::Timeouts::new(std::time::Duration::from_secs(1));
    let mut client = Client::new("127.0.0.1:48999", timeout, None).unwrap();
    let mut dev = client.device(ads::AmsAddr::new([1,2,3,4,5,6].into(), 851));
    let mut data = [0; 4];
    let now = std::time::Instant::now();
    for _ in 0..5000 {
        dev.read(0x4020, 0, &mut data).unwrap();
    }
    println!("client: {:?}", now.elapsed());
}

fn main() {
    main_dumb();
    main_client();
}
