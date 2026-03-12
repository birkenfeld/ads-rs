# `ads`

[![Build status](https://github.com/birkenfeld/ads-rs/actions/workflows/main.yml/badge.svg)](https://github.com/birkenfeld/ads-rs)
[![crates.io](https://img.shields.io/crates/v/ads.svg)](https://crates.io/crates/ads)
[![docs.rs](https://img.shields.io/docsrs/ads)](https://docs.rs/ads)

This crate allows to connect to [Beckhoff](https://beckhoff.com) TwinCAT devices
and other servers speaking the ADS (Automation Device Specification) protocol.

## Installation

Use with Cargo as usual, no system dependencies are required.

```toml
[dependencies]
ads = "0.5"
```

### Rust version

Minimum supported Rust version is 1.71.0.

## Usage

A simple example:

```rust
fn main() -> ads::Result<()> {
    // Open a connection to an ADS device identified by hostname/IP and port.
    // For TwinCAT devices, a route must be set to allow the client to connect.
    // The source AMS address is automatically generated from the local IP,
    // but can be explicitly specified as the third argument.
    let client = ads::Client::new(("plchost", ads::PORT), ads::Timeouts::none(),
                                  ads::Source::Auto)?;
    // On Windows, when connecting to a TwinCAT instance running on the same
    // machine, use the following to connect:
    let client = ads::Client::new(("127.0.0.1", ads::PORT), ads::Timeouts::none(),
                                  ads::Source::Request)?;

    // Specify the target ADS device to talk to, by NetID and AMS port.
    // Port 851 usually refers to the first PLC instance.
    let device = client.device(ads::AmsAddr::new([5, 32, 116, 5, 1, 1].into(), 851));

    // Ensure that the PLC instance is running.
    assert!(device.get_state()?.0 == ads::AdsState::Run);

    // Request a handle to a named symbol in the PLC instance.
    let handle = Handle::new(device, "MY_SYMBOL")?;

    // Read data in form of an u32 from the handle.
    let value: u32 = handle.read_value()?;
    println!("MY_SYMBOL value is {}", value);

    // Connection will be closed when the client is dropped.
    Ok(())
}
```

## Features

All ADS requests are implemented.

Further features include support for receiving notifications from a channel,
file access via ADS, and communication via UDP to identify an ADS system and set
routes automatically.

## Examples

A utility called `adstool` is found under `examples/`, very similar to the one
provided by [the C++ library](https://github.com/Beckhoff/ADS).

