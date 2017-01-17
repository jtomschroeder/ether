
extern crate ether;

use std::io;

use ether::pcap;
use ether::pcap::PacketCapture;
use ether::interconnect as ic;

fn run() -> io::Result<()> {
    use std::io::prelude::*;
    use std::fs::File;

    let mut buffer = Vec::new();
    let mut file = try!(File::open("etc/capture_tcp1.pcap"));
    try!(file.read_to_end(&mut buffer));

    let pcap = PacketCapture::new(buffer);
    let (pcap::Header { network, .. }, records) = pcap.parse().unwrap();

    for pcap::Record { payload, .. } in records {
        match network {
            pcap::Link::Ethernet => {
                let ethernet = ic::datalink::ethernet::Frame::new(payload);
                println!("ethernet: {:?}", ethernet);
            }
            _ => {}
        }
    }

    Ok(())
}

fn main() {
    run().unwrap();
}
