//! Shows how to read a whole structure from the PLC by handle,
//! by redefining it as a Rust struct with zerocopy traits.

use ads::{Client, Source, Timeouts, symbol::Handle};
use zerocopy::{AsBytes, FromZeroes, FromBytes};

#[derive(Default, AsBytes, FromZeroes, FromBytes)]
#[repr(packed)]
struct Motor {
    position: f32,
    speed: f32,
    moving: u8,
}

fn main() {
    let client = Client::new(("localhost", ads::PORT), Timeouts::none(), Source::Request).unwrap();
    let dev = client.device(ads::AmsAddr::new([5, 62, 215, 36, 1, 1].into(), 851));
    let handle = Handle::new(dev, "MY_SYMBOL").unwrap();
    let motor = handle.read_value::<Motor>().unwrap();
    let pos = motor.position;
    let spd = motor.speed;
    println!("Motor params: pos={} spd={} moving={}", pos, spd, motor.moving != 0);
}
