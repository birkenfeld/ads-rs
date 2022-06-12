//! Test for the TCP client.

use std::convert::TryFrom;
use std::io::{self, Read, Write};
use std::time::Duration;

use crate::test::{config_test_server, ServerOpts};
use crate::{AmsAddr, AmsNetId, Client, Device, Error, Source, Timeouts};

fn run_test(opts: ServerOpts, f: impl Fn(Device)) {
    let timeouts = if let Some(tmo) = opts.timeout {
        Timeouts::new(tmo)
    } else {
        Timeouts::none()
    };
    let port = config_test_server(opts);
    let client = Client::new(("127.0.0.1", port), timeouts, Source::Auto).unwrap();
    f(client.device(AmsAddr::new(AmsNetId::new(1, 2, 3, 4, 5, 6), 851)));
}

#[test]
fn test_garbage_packet() {
    run_test(ServerOpts { garbage_header: true, .. Default::default() }, |device| {
        let err = device.get_info().unwrap_err();
        assert!(matches!(err, Error::Reply(_, "invalid packet or unknown AMS command", _)));
    })
}

#[test]
fn test_timeout() {
    run_test(ServerOpts { timeout: Some(Duration::from_millis(1)),
                          no_reply: true,
                          .. Default::default() }, |device| {
        let err = device.get_info().unwrap_err();
        match err {
            Error::Io(_, ioe) if ioe.kind() == io::ErrorKind::TimedOut => (),
            _ => panic!("unexpected error from timeout: {}", err)
        }
    })
}

#[test]
fn test_wrong_invokeid() {
    run_test(ServerOpts { ignore_invokeid: true, .. Default::default() }, |device| {
        assert!(matches!(device.get_info().unwrap_err(),
                         Error::Reply(_, "unexpected invoke ID", 0)));
    })
}

#[test]
fn test_devinfo() {
    run_test(ServerOpts::default(), |device| {
        let info = device.get_info().unwrap();
        assert_eq!(info.version, 4024);
        assert_eq!(info.name, "Nice device");
    })
}

#[test]
fn test_state() {
    run_test(ServerOpts::default(), |device| {
        device.write_control(crate::AdsState::Config, 42).unwrap();
        assert_eq!(device.get_state().unwrap(), (crate::AdsState::Config, 42));
        assert!(device.write_control(crate::AdsState::Invalid, 42).is_err());
    })
}

#[test]
fn test_readwrite() {
    run_test(ServerOpts::default(), |device| {
        let data = [1, 6, 8, 9];
        let mut buf = [0; 4];
        device.write(0x4020, 7, &data).unwrap();
        device.read_exact(0x04020, 7, &mut buf).unwrap();
        assert_eq!(data, buf);

        assert!(matches!(device.read_exact(0x4021, 0, &mut buf),
                         Err(Error::Ads(_, _, 0x702))));
        assert!(matches!(device.read_exact(0x4020, 98765, &mut buf),
                         Err(Error::Ads(_, _, 0x703))));

        device.write_value(0x4020, 7, &0xdeadbeef_u32).unwrap();
        assert!(device.read_value::<u32>(0x4020, 7).unwrap() == 0xdeadbeef);
    })
}

#[test]
fn test_fileaccess() {
    use crate::file::*;
    run_test(ServerOpts::default(), |device| {
        assert!(File::open(device, "blub", 0).is_err());
        let mut file = File::open(device, "/etc/passwd", WRITE).unwrap();
        assert!(File::open(device, "/etc/passwd", 0).is_err());
        assert!(file.read(&mut [0; 4]).is_err());
        file.write_all(b"asdf").unwrap();
        file.flush().unwrap();
        drop(file);

        let mut file = File::open(device, "/etc/passwd", READ).unwrap();
        assert!(file.write(&[0; 4]).is_err());
        let mut vec = vec![];
        file.read_to_end(&mut vec).unwrap();
        assert!(vec.len() == 888);
        assert!(File::delete(device, "/etc/passwd", 0).is_err());
        drop(file);

        File::delete(device, "/etc/passwd", 0).unwrap();
    })
}

#[test]
fn test_symbolaccess() {
    use crate::symbol::*;
    run_test(ServerOpts::default(), |device| {
        assert!(Handle::new(device, "blub").is_err());
        let handle = Handle::new(device, "SYMBOL").unwrap();
        assert!(handle.write(&[1, 2, 3, 4, 5]).is_err());
        assert!(handle.read(&mut [0; 5]).is_err());

        handle.write(&[4, 3, 2, 1]).unwrap();
        let mut buf = [0; 4];
        handle.read(&mut buf).unwrap();
        assert!(buf == [4, 3, 2, 1]);

        handle.write_value(&0xdeadbeef_u32).unwrap();
        assert!(handle.read_value::<u32>().unwrap() == 0xdeadbeef);
    })
}

#[test]
fn test_notification() {
    use crate::notif::*;
    use std::time::Duration;
    run_test(ServerOpts::default(), |device| {
        let chan = device.client.get_notification_channel();

        let attrib = Attributes::new(4, TransmissionMode::ServerOnChange,
                                     Duration::from_secs(1), Duration::from_secs(1));
        device.write(0x4020, 0, &[4, 4, 1, 1]).unwrap();
        let handle = device.add_notification(0x4020, 0, &attrib).unwrap();
        device.write(0x4020, 0, &[8, 8, 1, 1]).unwrap();
        device.delete_notification(handle).unwrap();

        // Including the add_notification, each request generates a notification
        // from the test server.
        let first = chan.try_recv().unwrap();
        let second = chan.try_recv().unwrap();

        println!("{:?}", first);

        let mut samples = first.samples();
        assert_eq!(samples.next().unwrap(),
                   Sample { handle, timestamp: 0x9988776655443322, data: &[4, 4, 1, 1] });
        assert_eq!(samples.next(), None);
        assert_eq!(second.samples().next().unwrap(),
                   Sample { handle, timestamp: 0x9988776655443322, data: &[8, 8, 1, 1] });
    })
}

#[test]
fn test_bad_notification() {
    use crate::notif::*;
    use std::time::Duration;
    run_test(ServerOpts { bad_notif: true, .. Default::default() }, |device| {
        let chan = device.client.get_notification_channel();

        let attrib = Attributes::new(4, TransmissionMode::ServerOnChange,
                                     Duration::from_secs(1), Duration::from_secs(1));
        let _ = device.add_notification(0x4020, 0, &attrib).unwrap();
        device.write(0x4020, 0, &[8, 8, 1, 1]).unwrap();

        // No notification should have come through.
        assert!(chan.try_recv().is_err());

        // Notification is automatically deleted at end of scope.
    })
}

#[test]
fn test_string_type() {
    crate::make_string_type!(String5, 5);

    run_test(ServerOpts::default(), |device| {
        let mut bstr = String5::try_from("abc").unwrap();
        assert!(<[u8; 5]>::from(bstr) == [b'a', b'b', b'c', 0, 0]);
        assert!(bstr == &b"abc"[..]);
        assert!(bstr == "abc");
        assert!(bstr.len() == 3);
        assert!(bstr.backing_array().len() == 5);

        assert!(String5::try_from("abcdef").is_err());

        let bstr2 = String5::try_from(&b"abc"[..]).unwrap();
        assert!(<[u8; 5]>::from(bstr2) == [b'a', b'b', b'c', 0, 0]);
        assert!(bstr == bstr2);

        assert!(format!("{:?}", bstr) == "\"abc\"");

        device.write_value(0x4020, 7, &bstr).unwrap();

        let ret = device.read_value::<String5>(0x4020, 7).unwrap();
        assert!(<[u8; 5]>::from(ret) == [b'a', b'b', b'c', 0, 0]);
        assert!(String::try_from(ret).unwrap() == "abc");
        assert!(<Vec<u8>>::try_from(ret).unwrap() == [b'a', b'b', b'c']);
    })
}

#[test]
fn test_wstring_type() {
    crate::make_wstring_type!(WString5, 5);

    run_test(ServerOpts::default(), |device| {
        let mut wstr = WString5::try_from("abc").unwrap();
        assert!(<[u16; 5]>::from(wstr) == [b'a' as u16, b'b' as u16, b'c' as u16, 0, 0]);
        assert!(wstr == &[b'a' as u16, b'b' as u16, b'c' as u16][..]);
        assert!(wstr == "abc");
        assert!(wstr.len() == 3);
        assert!(wstr.backing_array().len() == 5);

        assert!(WString5::try_from(&[1, 2, 3, 4, 5, 6][..]).is_err());
        assert!(WString5::try_from("abcdef").is_err());

        assert!(format!("{:?}", wstr) == "\"abc\"");

        let wstr2 = WString5::try_from(&[b'a' as u16, b'b' as u16, b'c' as u16][..]).unwrap();
        assert!(<[u16; 5]>::from(wstr2) == [b'a' as u16, b'b' as u16, b'c' as u16, 0, 0]);
        assert!(wstr == wstr2);

        device.write_value(0x4020, 7, &wstr).unwrap();

        let ret = device.read_value::<WString5>(0x4020, 7).unwrap();
        assert!(<[u16; 5]>::from(ret) == [b'a' as u16, b'b' as u16, b'c' as u16, 0, 0]);
        assert!(String::try_from(ret).unwrap() == "abc");
        assert!(<Vec<u16>>::try_from(ret).unwrap() == [b'a' as u16, b'b' as u16, b'c' as u16]);
    })
}
