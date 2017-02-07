
/*!
Parse packet captures as a 'header' and list of 'records'

# Usage:
```rust,no_run
extern crate ether;
use ether::pcap;

fn run() -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Read;

    let mut buffer = Vec::new();
    let mut file = try!(File::open("capture.pcap"));
    try!(file.read_to_end(&mut buffer));

    let pcap = pcap::PacketCapture::new(buffer);
    let (_, records) = pcap.parse().unwrap();
    for record in records {
        match record {
            Ok(pcap::Record { payload, .. }) => println!("payload: {:?}", payload),
            _ => panic!("Failed to parse record!"),
        }
    }

    Ok(())
}

fn main() {
   run().unwrap();
}
```
*/

mod pcap;
pub use self::pcap::*;
