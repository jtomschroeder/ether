
# ether

[![crates.io](https://img.shields.io/crates/v/ether.svg)](https://crates.io/crates/ether)
![License](https://img.shields.io/github/license/jtomschroeder/ether.svg)

`ether` is a crate that provides a library parsing and manipulating network data, packet captures.

**NOTE:** `ether` is currently in the *alpha* phase (API is likely to change).

[Documentation](https://docs.rs/ether)

## Usage

Here's a simple example that prints all packets received on interface `en0`:

```rust
extern crate ether;

use ether::tap;
use ether::tap::Stream;

fn main() {
    let mut tap = tap::Tap::new("en0").unwrap();
    for packet in tap.stream().wait().filter_map(|p| p.ok()) {
        println!("{:?}", packet);
    }
}
```

## Framework

- `interconnect`
- `pcap`
- `tap`

## Tools

- `ethdump`
- Eventually...
  - `ping`
  - `trace-route`
