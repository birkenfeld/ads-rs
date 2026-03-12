use std::time::Duration;

use ads::notif::{Attributes, TransmissionMode};
use ads::{Client, Source, Timeouts};

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
    let dev = client.device(ads::AmsAddr::new([5, 62, 215, 36, 1, 1].into(), 851));
    let h1 = dev
        .add_notification(
            0x4020,
            4,
            &Attributes::new(
                4,
                TransmissionMode::ServerCycle,
                Duration::from_secs(1),
                Duration::from_secs(1),
            ),
        )
        .unwrap();
    let dev2 = client.device(ads::AmsAddr::new([5, 62, 215, 36, 1, 1].into(), 852));
    let h2 = dev2
        .add_notification(
            0x4020,
            0,
            &Attributes::new(
                4,
                TransmissionMode::ServerOnChange,
                Duration::from_secs(1),
                Duration::from_secs(1),
            ),
        )
        .unwrap();
    println!("{h1} {h2}");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
