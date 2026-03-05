use std::time::Duration;

use ads::notif::{Attributes, TransmissionMode};
use ads::{AmsAddr, AmsNetId, Client, Source, Timeouts};

const AMS_ADDR: AmsAddr = AmsAddr::new(AmsNetId([5, 62, 215, 36, 1, 1]), 851);
const NOTIF_ATTR: Attributes = Attributes::new(
    4,
    TransmissionMode::ServerOnChange,
    Duration::from_secs(1),
    Duration::from_secs(1),
);

fn main() {
    let client = Client::new(("127.0.0.1", ads::PORT), Timeouts::none(), Source::Request).unwrap();
    let recv_notify = client.get_notification_channel();

    std::thread::spawn(move || {
        for msg in recv_notify.iter() {
            for sample in msg.samples() {
                println!("notify: {sample:?}");
            }
        }
    });

    let dev = client.device(AMS_ADDR);
    let h1 = dev.add_notification(0x4020, 4, &NOTIF_ATTR).unwrap();

    let dev2 = client.device(AmsAddr::new([5, 62, 215, 36, 1, 1].into(), 852));
    let h2 = dev2.add_notification(0x4020, 0, &NOTIF_ATTR).unwrap();

    println!("{h1} {h2}");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
