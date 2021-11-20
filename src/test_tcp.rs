//! Test for the TCP client.

use crate::{AmsAddr, AmsNetId, Client, Device, Error, Timeouts};
use crate::testing::{ServerOpts, config_test_server};

fn run_test(opts: ServerOpts, f: impl Fn(Device)) {
    let port = config_test_server(opts);
    let timeouts = Timeouts::none();
    let client = Client::new(("127.0.0.1", port), timeouts, None).unwrap();
    f(client.device(AmsAddr::new(AmsNetId::new(1, 2, 3, 4, 5, 6), 851)));
}

#[test]
fn test_garbage_packet() {
    run_test(ServerOpts { garbage_header: true, .. Default::default() }, |device| {
        let err = device.get_info().unwrap_err();
        assert!(matches!(err, Error::Reply(_, "inconsistent packet", _)));
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
fn test_readwrite() {
    run_test(ServerOpts::default(), |device| {
        let data = [1, 6, 8, 9];
        let mut buf = [0; 4];
        device.write(0x4020, 7, &data).unwrap();
        device.read(0x04020, 7, &mut buf).unwrap();
        assert_eq!(data, buf);

        assert!(matches!(device.read(0x4021, 0, &mut buf),
                         Err(Error::Ads(_, _, 0x702))));
        assert!(matches!(device.read(0x4020, 98765, &mut buf),
                         Err(Error::Ads(_, _, 0x703))));
    })
}

#[test]
fn test_state() {
    run_test(ServerOpts::default(), |device| {
        device.write_control(crate::tcp::AdsState::Config, 42).unwrap();
        assert_eq!(device.get_state().unwrap(), (crate::tcp::AdsState::Config, 42));
        assert!(device.write_control(crate::tcp::AdsState::Invalid, 42).is_err());
    })
}
