
/// PCAP Header
///
/// * magic number (0xA1B23C4D)
/// * major version number
/// * minor version number
/// * GMT to local correction
/// * accuracy of timestamps (typically ignored as 0)
/// * max length of captured packets, in octets
/// * data link type
///
#[derive(Debug)]
pub struct Header {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: Link,
}

/// Link types as defined in http://www.tcpdump.org/linktypes.html
#[derive(Debug)]
pub enum Link {
    Null,
    Ethernet,
    Unknown(u32),
}

impl From<u32> for Link {
    fn from(link: u32) -> Self {
        match link {
            0 => Link::Null,
            1 => Link::Ethernet,
            otherwise => Link::Unknown(otherwise),
        }
    }
}

/// Record entry in a packet capture
///
/// * timestamp seconds
/// * timestamp nanoseconds
/// * number of octets of packet saved in file
/// * actual length of packet
#[derive(Debug)]
pub struct Record {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
    pub payload: Vec<u8>,
}

use std::io;
use std::io::{Read, BufReader};

struct Buffer<R>(BufReader<R>);

impl<R: Read> Buffer<R> {
    fn take(&mut self, length: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0; length];
        self.0.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn take_i32(&mut self) -> io::Result<i32> {
        let buffer = self.take(4)?;
        Ok((buffer[0] as i32) + ((buffer[1] as i32) << 8) + ((buffer[2] as i32) << 16) +
           ((buffer[3] as i32) << 24))
    }

    fn take_u32(&mut self) -> io::Result<u32> {
        let buffer = self.take(4)?;
        Ok((buffer[0] as u32) + ((buffer[1] as u32) << 8) + ((buffer[2] as u32) << 16) +
           ((buffer[3] as u32) << 24))
    }

    fn take_u16(&mut self) -> io::Result<u16> {
        let buffer = self.take(2)?;
        Ok((buffer[0] as u16) + ((buffer[1] as u16) << 8))
    }
}

/// PacketCapture: container for pcap byte-stream
pub struct PacketCapture<R> {
    capture: Buffer<R>,
}

impl<R: Read> PacketCapture<R> {
    pub fn new(capture: R) -> PacketCapture<R> {
        PacketCapture { capture: Buffer(BufReader::new(capture)) }
    }
}

impl Header {
    fn parse<R: Read>(data: &mut Buffer<R>) -> io::Result<Header> {
        Ok(Header {
               magic_number: data.take_u32()?,
               version_major: data.take_u16()?,
               version_minor: data.take_u16()?,
               thiszone: data.take_i32()?,
               sigfigs: data.take_u32()?,
               snaplen: data.take_u32()?,
               network: Link::from(data.take_u32()?),
           })
    }
}

impl Record {
    fn parse<R: Read>(data: &mut Buffer<R>) -> io::Result<Record> {
        let ts_sec = data.take_u32()?;
        let ts_usec = data.take_u32()?;
        let incl_len = data.take_u32()?;
        let orig_len = data.take_u32()?;
        let payload = data.take(incl_len as usize)?;

        Ok(Record {
               ts_sec: ts_sec,
               ts_usec: ts_usec,
               incl_len: incl_len,
               orig_len: orig_len,
               payload: payload,
           })
    }
}

impl<R: Read> PacketCapture<R> {
    pub fn parse(mut self) -> io::Result<(Header, Records<R>)> {
        Ok((Header::parse(&mut self.capture)?, Records { capture: self.capture }))
    }
}

pub struct Records<R> {
    capture: Buffer<R>,
}

impl<R: Read> Iterator for Records<R> {
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        Record::parse(&mut self.capture).ok()
    }
}
