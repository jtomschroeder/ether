
extern crate ether;
use ether::tap;

fn main() {
    let mut tap = tap::Tap::new("en0").unwrap();

    // UDP/IPv4 (`echo 'test' | nc -u localhost 2389`)
    // NOTE: sending on a 'loopback' tap doesn't require a datalink header (e.g. ethernet)
    let data = [69, 0, 0, 33, 178, 156, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1, 240, 186,
                9, 85, 0, 13, 254, 32, 116, 101, 115, 116, 10];

    let mut sink = tap.sink();
    sink.send(&data).unwrap();
}
