
extern crate ether;
extern crate libc;
extern crate itertools;

use std::io;
use std::ptr;
use std::time::Duration;
use itertools::Itertools;

use ether::packet::network::{ipv4, icmp};

// from /usr/include/netinet/in.h
const IPPROTO_ICMP: libc::c_int = 1;
const IP_MAXPACKET: usize = 65535; // maximum packet size

// from /usr/include/netinet/ip_icmp.h
// ICMP_ECHOREPLY          0
// ICMP_ECHO               8

fn pselect(nfds: libc::c_int,
           readfds: Option<&mut libc::fd_set>,
           writefds: Option<&mut libc::fd_set>,
           timeout: Option<Duration>)
           -> io::Result<()> {
    let timeout = timeout.map(|d| {
        libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        }
    });

    let ret = unsafe {
        libc::pselect(nfds + 1,
                      readfds.map(|to| to as *mut libc::fd_set)
                          .unwrap_or(ptr::null_mut()),
                      writefds.map(|to| to as *mut libc::fd_set)
                          .unwrap_or(ptr::null_mut()),
                      ptr::null_mut(),
                      timeout.as_ref()
                          .map(|to| to as *const libc::timespec)
                          .unwrap_or(ptr::null()),
                      ptr::null())
    };

    match ret {
        -1 => Err(io::Error::last_os_error()), // Error occured!
        0 => Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")),
        _ => Ok(()),
    }
}

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

        {
            let buffer = vec![0u8; IP_MAXPACKET];
            let addrlen = 16u32;
            let recvd = match recvfrom(s,
                                       mem::transmute(buffer.as_ptr()),
                                       buffer.len(),
                                       0,
                                       mem::transmute(&whereto),
                                       mem::transmute(&addrlen)) {
                -1 => {
                    println!("ERROR! [recvfrom] {}", std::io::Error::last_os_error());
                    return;
                }
                otherwise => otherwise as usize,
            };

            println!("{:?}", recvd);

            let packet = &buffer[0..recvd];
            println!("{:?}", packet);

            let packet = ipv4::Packet::new(packet);
            println!("{:?}", packet);

            let hlen = (packet.ihl() << 2) as usize;
            let packet = &buffer[hlen..recvd];
            let packet = icmp::Packet::new(packet);
            println!("{:?}", packet);
        }

        close(s);
    }
}
