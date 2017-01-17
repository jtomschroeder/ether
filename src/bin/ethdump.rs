
extern crate futures;
extern crate ether;

use futures::stream::Stream;
use ether::tap;
use ether::interconnect as ic;

fn main() {
    let mut tap = tap::Tap::new("en0").unwrap();
    // let mut tap = tap::Tap::new("lo0").unwrap();

    for packet in tap.stream().wait().filter_map(|p| p.ok()) {
        let ethernet = ic::datalink::ethernet::Frame::new(&packet);
        // println!("{:?}", ethernet);

        if ethernet.ethertype() == ic::datalink::ethernet::EtherType::IPv4 {
            let ip = ic::network::ipv4::Packet::new(ethernet.payload());
            // println!("{:?}", ip);

            if ip.protocol() == ic::network::ipv4::Protocol::TCP {
                let tcp = ic::transport::tcp::Packet::new(ip.payload());
                println!("{:#?}", tcp);
            }
        }
    }
}
