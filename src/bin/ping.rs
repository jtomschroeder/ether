
extern crate ether;
extern crate libc;
extern crate itertools;

use std::io;
use std::mem;
use std::net;

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
use std::ops;

use nix::fcntl::{fcntl, FcntlArg, O_NONBLOCK};

use mio::Evented;
use mio::unix::EventedFd;
use tokio_core::reactor::{Core, Handle, PollEvented};
use futures::{Stream, Poll, Async};

#[derive(Debug)]
pub struct RawSocket(RawFd);

impl RawSocket {
    fn new() -> io::Result<Self> {
        use libc::*;
        match unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) } {
            -1 => Err(io::Error::last_os_error()),
            s => Ok(RawSocket(s)),
        }
    }

    fn raw(&self) -> RawFd {
        self.0
    }

    fn recv_from(&self, buffer: &mut [u8], addr: net::Ipv4Addr) -> io::Result<usize> {
        let whereto = destination(addr);
        let addrlen = 16u32;

        unsafe {
            match libc::recvfrom(self.raw(),
                                 mem::transmute(buffer.as_ptr()),
                                 buffer.len(),
                                 0,
                                 mem::transmute(&whereto),
                                 mem::transmute(&addrlen)) {
                -1 => Err(io::Error::last_os_error()),
                otherwise => Ok(otherwise as usize),
            }
        }
    }
}

impl<'a> Evented for &'a RawSocket {
    fn register(&self,
                poll: &mio::Poll,
                token: mio::Token,
                interest: mio::Ready,
                opts: mio::PollOpt)
                -> io::Result<()> {
        EventedFd(&self.raw()).register(poll, token, interest, opts)
    }

    fn reregister(&self,
                  poll: &mio::Poll,
                  token: mio::Token,
                  interest: mio::Ready,
                  opts: mio::PollOpt)
                  -> io::Result<()> {
        EventedFd(&self.raw()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        EventedFd(&self.raw()).deregister(poll)
    }
}

pub struct RawSocketStream<'a> {
    socket: &'a RawSocket,
    evented: PollEvented<&'a RawSocket>,
}

impl<'a> RawSocketStream<'a> {
    pub fn new<'s>(socket: &'s RawSocket, handle: &Handle) -> io::Result<RawSocketStream<'s>> {
        Ok(RawSocketStream {
            socket: socket,
            evented: try!(PollEvented::new(socket, &handle)),
        })
    }
}

fn destination(addr: net::Ipv4Addr) -> libc::sockaddr_in {
    // let addr = net::Ipv4Addr::new(216, 58, 216, 238); // google.com

    let mut whereto: libc::sockaddr_in = unsafe { mem::zeroed() };
    whereto.sin_family = libc::AF_INET as u8;
    whereto.sin_len = 16; // sizeof(sockaddr_in)

    let addr: u32 = addr.into();
    whereto.sin_addr.s_addr = addr.to_be();

    whereto
}

impl<'a> Stream for RawSocketStream<'a> {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        Ok(match self.evented.poll_read() {
            Async::Ready(_) => {
                let mut buffer = vec![0u8; IP_MAXPACKET];
                let addr = net::Ipv4Addr::new(216, 58, 216, 238);
                let recvd = try!(self.socket.recv_from(&mut buffer, addr));
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

    let addr = net::Ipv4Addr::new(216, 58, 216, 238); // google.com

    let s = unsafe {
        use std::mem;
        use libc::*;

        let s = try!(RawSocket::new());

        let whereto = destination(addr);

        // Send echo request
        let i = sendto(s.raw(),
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

    try!(fcntl(s.raw(), FcntlArg::F_SETFL(O_NONBLOCK)));

    let stream = try!(RawSocketStream::new(&s, &handle));

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
        libc::close(s.raw());
    }

    Ok(())
}

fn main() {
    run().unwrap();
}
