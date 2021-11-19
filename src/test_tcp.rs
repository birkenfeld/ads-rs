//! Test for the TCP client.

use crate::{AmsAddr, AmsNetId, Client, Device, Timeouts};
use crate::testing::start_test_server;

fn run_test(f: impl Fn(Device)) {
    start_test_server();
    let timeouts = Timeouts::none();
    let client = Client::new("127.0.0.1:49000", timeouts, None).unwrap();
    f(client.device(AmsAddr::new(AmsNetId::new(1, 2, 3, 4, 5, 6), 851)));
}

#[test]
fn test_devinfo() {
    run_test(|device| {
        let info = device.get_info().unwrap();
        assert_eq!(info.version, 4024);
        assert_eq!(info.name, "Nice device");
    })
}
