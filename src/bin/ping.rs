
extern crate ether;
extern crate libc;
extern crate itertools;

use itertools::Itertools;

use ether::packet::network::{ipv4, icmp};

// from /usr/include/netinet/in.h
const IPPROTO_ICMP: libc::c_int = 1;
const IP_MAXPACKET: libc::c_int = 65535; // maximum packet size

// from /usr/include/netinet/ip_icmp.h
// ICMP_ECHOREPLY          0
// ICMP_ECHO               8

fn main() {
    let packet = icmp::Builder::new()
        .class(8)
        .code(0)
        .identifier(51123)
        .sequence(0)
        .build("TEST".as_bytes());

    unsafe {
        use std::mem;
        use libc::*;

        let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if s < 0 {
            println!("ERROR! [socket] {}", std::io::Error::last_os_error());
            return;
        }

        let mut whereto: sockaddr_in = mem::zeroed(); // who to ping
        whereto.sin_family = AF_INET as u8;
        whereto.sin_len = 16; // sizeof sockaddr_in
        whereto.sin_addr.s_addr = 0xEED83AD8; // google.com @ 216.58.216.238 (little endian)

        // let hold = IP_MAXPACKET + 128;
        // setsockopt(s, SOL_SOCKET, SO_RCVBUF, mem::transmute(&hold), 4);

        // Send echo request
        let i = sendto(s,
                       mem::transmute(packet.as_ptr()),
                       packet.len(),
                       0,
                       mem::transmute(&whereto),
                       16);
        if i < 0 {
            println!("ERROR! [sendto] {}", std::io::Error::last_os_error());
            return;
        }

        close(s);
    }
}
