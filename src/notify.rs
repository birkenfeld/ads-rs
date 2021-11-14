//! Everything to do with ADS notifications.

use std::time::Duration;

/// A single notification message from the ADS server.
pub struct Notification(Vec<u8>);

impl Notification {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

/// A handle to the notification; this can be used to delete the notification later.
pub type Handle = u32;

/// Attributes for creating a notification.
pub struct Attributes {
    pub length: usize,
    pub trans_mode: TransmissionMode,
    pub max_delay: Duration,
    pub cycle_time: Duration,
}

impl Attributes {
    pub fn new(length: usize, trans_mode: TransmissionMode,
               max_delay: Duration, cycle_time: Duration) -> Self {
        Self { length, trans_mode, max_delay, cycle_time  }
    }
}

/// When notifications should be generated.
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum TransmissionMode {
    NoTrans = 0,
    ClientCycle = 1,
    Client1Req = 2,
    ServerCycle = 3,
    ServerOnChange = 4,
}
