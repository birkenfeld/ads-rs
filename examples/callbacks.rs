use std::time::Duration;

use ads::{
    index,
    notif::{Attributes, TransmissionMode},
    AmsAddr, AmsNetId, Client, Source, Timeouts,
};
use zerocopy::{TryFromBytes, LE, U32};
use crossbeam_channel::unbounded;

const AMS_ADDR: AmsAddr = AmsAddr::new(AmsNetId([5, 62, 215, 36, 1, 1]), 851);
const NOTIF_ATTR: Attributes = Attributes::new(
    4,
    TransmissionMode::ServerOnChange,
    Duration::from_secs(1),
    Duration::from_secs(1),
);

fn main() {
    let client = Client::new(("127.0.0.1", ads::PORT), Timeouts::none(), Source::Request).unwrap();

    let dev = client.device(AMS_ADDR);
    let (tx, rx) = unbounded();
    let cb_handle = dev
        .add_callback(index::PLC_RW_M, 0, &NOTIF_ATTR, move |sample| {
            tx.send(sample.data.to_vec()).unwrap();
        })
        .unwrap();

    dev.write_value(index::PLC_RW_M, 0, &42).unwrap();
    dev.remove_callback(cb_handle).unwrap();

    let samples = rx
        .into_iter()
        .map(|d| U32::<LE>::try_read_from_bytes(&d[..]).unwrap().get())
        .collect::<Vec<_>>();

    assert!(matches!(&samples[..], [_, 42]));

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
