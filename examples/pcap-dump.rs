
extern crate ether;

use ether::pcap;

fn run() -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Read;

    let mut buffer = Vec::new();
    let mut file = try!(File::open("etc/capture_tcp1.pcap"));
    try!(file.read_to_end(&mut buffer));

    let pcap = pcap::PacketCapture::new(buffer);
    match pcap.parse().unwrap() {
        (pcap::Header { network: pcap::Link::Ethernet, .. }, records) => {
            for pcap::Record { payload, .. } in records {
                println!("ethernet: {:?}", payload);
            }
        }
        _ => {}
    }

    Ok(())
}

fn main() {
    run().unwrap();
}
