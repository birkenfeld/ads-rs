//! Shows how to read a whole structure from the PLC by handle,
//! by redefining it as a Rust struct with zerocopy traits.

use ads::{symbol::Handle, Client, Source, Timeouts};
use zerocopy::{FromBytes, IntoBytes};

#[derive(Default, FromBytes, IntoBytes)]
#[repr(packed)]
struct Motor {
    position: f32,
    speed: f32,
    moving: u8,
}

fn main() {
    let client = Client::new(("127.0.0.1", ads::PORT), Timeouts::none(), Source::Request).unwrap();
    let dev = client.device(ads::AmsAddr::new([5, 62, 215, 36, 1, 1].into(), 851));
    let handle = Handle::new(dev, "MY_SYMBOL").unwrap();
    let motor = handle.read_value::<Motor>().unwrap();
    let pos = motor.position;
    let spd = motor.speed;
    println!(
        "Motor params: pos={} spd={} moving={}",
        pos,
        spd,
        motor.moving != 0
    );
}
