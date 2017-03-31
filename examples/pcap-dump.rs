
extern crate ether;

use ether::pcap;

fn run() -> std::io::Result<()> {
    use std::fs::File;
    let file = try!(File::open("etc/capture_tcp1.pcap"));

    let pcap = pcap::PacketCapture::new(file);
    let (_, records) = pcap.parse().unwrap();
    for pcap::Record { payload, .. } in records {
        println!("payload: {:?}", payload);
    }

    Ok(())
}

fn main() {
    run().unwrap();
}
