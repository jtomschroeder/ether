
extern crate ether;

use ether::tap;
use ether::tap::Stream;

fn main() {
    let mut tap = tap::Tap::new("en0").expect("tap::en0");
    for packet in tap.stream().wait().filter_map(|p| p.ok()) {
        println!("{:?}", packet);
    }
}
