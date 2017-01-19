
extern crate ether;

use ether::tap;
use ether::tap::Stream;
use ether::packet::{datalink, network, transport};

fn main() {
    let mut tap = tap::Tap::new("en0").unwrap();
    for packet in tap.stream().wait().filter_map(|p| p.ok()) {
        let ethernet = datalink::ethernet::Frame::new(&packet);

        if ethernet.ethertype() == datalink::ethernet::EtherType::IPv4 {
            let ip = network::ipv4::Packet::new(ethernet.payload());

            if ip.protocol() == network::ipv4::Protocol::TCP {
                let tcp = transport::tcp::Packet::new(ip.payload());
                println!("{:#?}", tcp);
            }
        }
    }
}
