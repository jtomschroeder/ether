
extern crate futures;
extern crate ether;

use futures::stream::Stream;
use ether::tap;

fn main() {
    let mut tap = tap::Tap::new("en0").unwrap();
    // let mut tap = tap::Tap::new("lo0").unwrap();

    for packet in tap.stream().wait().filter_map(|p| p.ok()) {
        println!("{:?}", packet);
    }
}
