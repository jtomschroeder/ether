
extern crate ether;
extern crate libc;
extern crate itertools;

use itertools::Itertools;

// use ether::packet::datalink::ethernet;
use ether::packet::network::{ipv4, icmp};
// use ether::tap;
// use ether::tap::bpf;

// from /usr/include/netinet/in.h
const IPPROTO_ICMP: libc::c_int = 1;
const IP_MAXPACKET: libc::c_int = 65535; // maximum packet size

// from /usr/include/netinet/ip_icmp.h
// ICMP_ECHOREPLY          0
// ICMP_ECHO               8

// #[cfg_attr(rustfmt, rustfmt_skip)]
fn main() {
    println!("HELLO!");

    // let packet = [0x45, 0x00, 0x00, 0x54, 0xdf, 0x03, 0x00, 0x00, 0x40, 0x01, 0xdd, 0xe1, 0x0a,
    //               0x00, 0x00, 0xdd, 0xac, 0xd9, 0x06, 0x0e, 0x08, 0x00, 0x05, 0xcd, 0xee, 0x61,
    //               0x00, 0x00, 0x58, 0x83, 0xe1, 0x82, 0x00, 0x0e, 0xde, 0xb9, 0x08, 0x09, 0x0a,
    //               0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    //               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    //               0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
    //               0x32, 0x33, 0x34, 0x35, 0x36, 0x37];

    // let packet = ethernet::Builder::new().build(&packet);

    let packet = icmp::Builder::new().build("TEST".as_bytes());

    // let packet = [0x8, 0x0, 0x51, 0x73, 0xA6, 0x8C, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    //               0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    //               0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    //               0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    //               0x0];

    // let ethernet = ethernet::Frame::new(&packet);
    // println!("ETH: {:#?}", ethernet);

    // let ip = ipv4::Packet::new(&packet);
    // println!("IP: {:#?}", ip);

    let icmp = icmp::Packet::new(&packet);
    println!("ICMP: {:#?}", icmp);

    // let mut tap = tap::Tap::new("en0").unwrap();
    // let mut sink = tap.sink();
    // sink.send(&packet).unwrap();

    unsafe {
        use std::mem;
        use libc::*;

        // 0xADC24A71; // 173.194.74.113 (google.com)

        let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if s < 0 {
            println!("ERROR! socket() failed");
            return;
        }

        let mut whereto: sockaddr_in = mem::zeroed(); // who to ping
        whereto.sin_family = AF_INET as u8;
        whereto.sin_len = 16; // sizeof sockaddr_in
        whereto.sin_addr.s_addr = 0xEED83AD8; // google.com @ 216.58.216.238 (little endian)

        // let hold = IP_MAXPACKET + 128;
        // setsockopt(s, SOL_SOCKET, SO_RCVBUF, mem::transmute(&hold), 4);

        // println!("{:?}", checksum(&packet[..], 1));

        // pinger
        let i = sendto(s,
                       mem::transmute((&packet).as_ptr()),
                       packet.len(),
                       0,
                       mem::transmute(&whereto),
                       16);
        if i < 0 {
            println!("ERROR! {}", std::io::Error::last_os_error());
            return;
        }

        close(s);
    }
}

// IP 10.231.40.139 > 113.74.194.173: ICMP echo request, id 51123, seq 1, length 12
//  f43e 9d03 5315 784f 4352 575f 0800 4500  .>..S.xOCRW_..E.
//  0020 d0e3 0000 4001 4290 0ae7 288b 714a  ......@.B...(.qJ
//  c2ad 0800 88b1 c7b3 0001 5445 5354       ..........TEST

// IP 10.231.40.139 > 216.58.216.238: ICMP echo request, id 29849, seq 0, length 64
//  f43e 9d03 5315 784f 4352 575f 0800 4500  .>..S.xOCRW_..E.
//  0054 1410 0000 4001 81fe 0ae7 288b d83a  .T....@.....(..:
//  d8ee 0800 d7cd 7499 0000 5885 47a6 000a  ......t...X.G...
//  2060 0809 0a0b 0c0d 0e0f 1011 1213 1415  .`..............
//  1617 1819 1a1b 1c1d 1e1f 2021 2223 2425  ...........!"#$%
//  2627 2829 2a2b 2c2d 2e2f 3031 3233 3435  &'()*+,-./012345
//  3637                                     67
