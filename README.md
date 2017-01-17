
# ether

[![crates.io](https://img.shields.io/crates/v/ether.svg)](https://crates.io/crates/ether)
![License](https://img.shields.io/crates/l/ether.svg)

`ether` is a library for parsing and manipulating network data, packet captures.

**NOTE:** `ether` is currently in the *alpha* phase (API is likely to change).

## Documentation

On its way!

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
ether = "0.0"
```

and this to *root* of your crate:

```rs
extern crate ether;
```

Here's a simple example that prints all packets received on interface `en0`:

```rs
extern crate futures;
extern crate ether;

use futures::stream::Stream;
use ether::tap;

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
