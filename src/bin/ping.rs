
extern crate ether;
extern crate libc;
extern crate itertools;

use std::io;
use std::mem;

use ether::packet::network::{ipv4, icmp};

// from /usr/include/netinet/in.h
const IPPROTO_ICMP: libc::c_int = 1;
const IP_MAXPACKET: usize = 65535; // maximum packet size

// from /usr/include/netinet/ip_icmp.h
// ICMP_ECHOREPLY          0
// ICMP_ECHO               8

extern crate mio;
extern crate tokio_core;
extern crate futures;
extern crate nix;

use std::os::unix::io::RawFd;
use nix::fcntl::{fcntl, FcntlArg, O_NONBLOCK};

use mio::Evented;
use mio::unix::EventedFd;
use tokio_core::reactor::{Core, Handle, PollEvented};
use futures::{Stream, Poll, Async};

#[derive(Debug)]
pub struct EventedFile {
    fd: RawFd,
}

impl Evented for EventedFile {
    fn register(&self,
                poll: &mio::Poll,
                token: mio::Token,
                interest: mio::Ready,
                opts: mio::PollOpt)
                -> io::Result<()> {
        EventedFd(&self.fd).register(poll, token, interest, opts)
    }

    fn reregister(&self,
                  poll: &mio::Poll,
                  token: mio::Token,
                  interest: mio::Ready,
                  opts: mio::PollOpt)
                  -> io::Result<()> {
        EventedFd(&self.fd).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        EventedFd(&self.fd).deregister(poll)
    }
}

pub struct RawSocketStream {
    fd: RawFd,
    evented: PollEvented<EventedFile>,
}

impl RawSocketStream {
    pub fn new(evf: EventedFile, handle: &Handle) -> io::Result<Self> {
        Ok(RawSocketStream {
            fd: evf.fd,
            evented: try!(PollEvented::new(evf, &handle)),
        })
    }
}

fn destination() -> libc::sockaddr_in {
    let mut whereto: libc::sockaddr_in = unsafe { mem::zeroed() }; // who to ping
    whereto.sin_family = libc::AF_INET as u8;
    whereto.sin_len = 16; // sizeof sockaddr_in
    whereto.sin_addr.s_addr = 0xEED83AD8; // google.com @ 216.58.216.238 (little endian)
    whereto
}

impl Stream for RawSocketStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        Ok(match self.evented.poll_read() {
            Async::Ready(_) => {
                self.evented.need_read();

                let buffer = vec![0u8; IP_MAXPACKET];
                let addrlen = 16u32;

                let whereto = destination();

                let recvd = unsafe {
                    match libc::recvfrom(self.fd,
                                         mem::transmute(buffer.as_ptr()),
                                         buffer.len(),
                                         0,
                                         mem::transmute(&whereto),
                                         mem::transmute(&addrlen)) {
                        -1 => return Err(io::Error::last_os_error()),
                        otherwise => otherwise as usize,
                    }
                };

                Async::Ready(Some(buffer[..recvd].to_vec()))
            }
            Async::NotReady => Async::NotReady,
        })
    }
}

fn run() -> io::Result<()> {
    let packet = icmp::Builder::new()
        .class(8)
        .code(0)
        .identifier(51123)
        .sequence(0)
        .build("TEST".as_bytes());

    let s = unsafe {
        use std::mem;
        use libc::*;

        let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if s < 0 {
            return Err(io::Error::last_os_error());
        }

        let whereto = destination();

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
            return Err(io::Error::last_os_error());
        }

        s
    };

    let mut core = try!(Core::new());
    let handle = core.handle();

    try!(fcntl(s, FcntlArg::F_SETFL(O_NONBLOCK)));

    let stream = try!(RawSocketStream::new(EventedFile { fd: s }, &handle));

    try!(core.run(stream.take(1).for_each(|buffer| {
        println!("{:?}", buffer);

        let packet = ipv4::Packet::new(&buffer);
        println!("{:?}", packet);

        let hlen = (packet.ihl() << 2) as usize;
        let packet = &buffer[hlen..];
        let packet = icmp::Packet::new(packet);
        println!("{:?}", packet);

        Ok(())
    })));

    unsafe {
        libc::close(s);
    }

    Ok(())
}

fn main() {
    run().unwrap();
}
