
/*!
This crate provides a library for parsing and manipulating network data, packet captures.

# Usage

Add `ether` to the dependencies in your `Cargo.toml` and the following to *root* of your crate:

```rust
extern crate ether;
```

Here's a simple example that prints all packets received on interface `en0`:

```rust,no_run
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
*/

extern crate num;
extern crate libc;
extern crate glob;
extern crate futures;

mod utility;

pub mod packet;
pub mod pcap;
pub mod tap;
