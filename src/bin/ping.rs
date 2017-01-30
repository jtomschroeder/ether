
extern crate mio;
extern crate tokio_core;
extern crate futures;
extern crate nix;

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

use std::os::unix::io::RawFd;
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

    fn send_to(&self, buf: &[u8], addr: net::Ipv4Addr) -> io::Result<usize> {
        let whereto = destination(addr);
        let addrlen = mem::size_of::<libc::sockaddr_in>() as u32;

        match unsafe {
            libc::sendto(self.raw(),
                         mem::transmute(buf.as_ptr()),
                         buf.len(),
                         0,
                         mem::transmute(&whereto),
                         addrlen)
        } {
            -1 => Err(io::Error::last_os_error()),
            otherwise => Ok(otherwise as usize),
        }
    }

    fn recv_from(&self, buf: &mut [u8], addr: net::Ipv4Addr) -> io::Result<usize> {
        let whereto = destination(addr);
        let addrlen = mem::size_of::<libc::sockaddr_in>();

        match unsafe {
            libc::recvfrom(self.raw(),
                           mem::transmute(buf.as_ptr()),
                           buf.len(),
                           0,
                           mem::transmute(&whereto),
                           mem::transmute(&addrlen))
        } {
            -1 => Err(io::Error::last_os_error()),
            otherwise => Ok(otherwise as usize),
        }
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        try!(fcntl(self.raw(), FcntlArg::F_SETFL(O_NONBLOCK)));
        Ok(())
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.raw());
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
    buffer: Vec<u8>,
}

impl<'a> RawSocketStream<'a> {
    pub fn new<'s>(socket: &'s RawSocket, handle: &Handle) -> io::Result<RawSocketStream<'s>> {
        Ok(RawSocketStream {
            socket: socket,
            evented: try!(PollEvented::new(socket, &handle)),
            buffer: vec![0u8; IP_MAXPACKET],
        })
    }
}

fn destination(addr: net::Ipv4Addr) -> libc::sockaddr_in {
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
                let addr = net::Ipv4Addr::new(216, 58, 216, 238);
                let recvd = try!(self.socket.recv_from(&mut self.buffer, addr));
                Async::Ready(Some(self.buffer[..recvd].to_vec()))
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

    let socket = try!(RawSocket::new());
    try!(socket.set_nonblocking());

    // Send echo request
    try!(socket.send_to(&packet, addr));

    let mut core = try!(Core::new());
    let handle = core.handle();

    let stream = try!(RawSocketStream::new(&socket, &handle));

    try!(core.run(stream.take(1).for_each(|buffer| {
        let packet = ipv4::Packet::new(&buffer);
        println!("{:?}", packet);

        let hlen = (packet.ihl() << 2) as usize;
        let packet = &buffer[hlen..];
        let packet = icmp::Packet::new(packet);
        println!("{:?}", packet);

        Ok(())
    })));

    Ok(())
}

fn main() {
    run().unwrap();
}
