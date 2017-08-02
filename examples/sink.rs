
extern crate ether;
use ether::tap;

fn main() {
    let mut tap = tap::Tap::new("lo0").unwrap();

    let mut sink = tap.sink();

    // UDP/IPv4 (`echo 'test' | nc -u localhost 2389`)
    let data = [69, 0, 0, 33, 178, 156, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1, 240, 186,
                9, 85, 0, 13, 254, 32, 116, 101, 115, 116, 10];
    sink.send(&data).unwrap();
}
