
use std::ops;
use std::fmt;
use utility::parser;

pub struct Frame<'a>(&'a [u8]);

#[doc(hidden)]
impl<'a> ops::Deref for Frame<'a> {
    type Target = &'a [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> Frame<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Frame(data)
    }

    pub fn destination(&self) -> &[u8] {
        &self[..6]
    }

    pub fn source(&self) -> &[u8] {
        &self[6..12]
    }

    pub fn ethertype(&self) -> EtherType {
        parser::be_u16(&self[12..]).into()
    }

    pub fn payload(&self) -> &[u8] {
        &self[14..]
    }
}

impl<'a> fmt::Debug for Frame<'a> {
    fn fmt(&self, fmtr: &mut fmt::Formatter) -> fmt::Result {
        fmtr.debug_struct("ethernet::Frame")
            .field("destination", &self.destination())
            .field("source", &self.source())
            .field("ethertype", &self.ethertype())
            .field("payload", &self.payload())
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        use self::EtherType::*;
        match value {
            0x0800 => IPv4,
            0x0806 => ARP,
            0x86DD => IPv6,
            otherwise => Unknown(otherwise),
        }
    }
}

pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub fn octets(&self) -> &[u8] {
        &self.0
    }
}

pub struct Builder {
    destination: MacAddr,
    source: MacAddr,
    ethertype: EtherType,
}


impl Builder {
    pub fn new() -> Self {
        Builder {
            destination: MacAddr([0; 6]),
            source: MacAddr([0; 6]),
            ethertype: EtherType::Unknown(0),
        }
    }

    pub fn build(&self, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![];
        frame.extend(&[0x4a, 0x1d, 0x70, 0x19, 0x45, 0xef]); // TODO: self.destination.octets());
        frame.extend(&[0x78, 0x4f, 0x43, 0x52, 0x57, 0x5f]); // TODO: self.source.octets());
        frame.extend(&[0x08, 0x00]); // TODO: ether-type
        frame.extend(payload);
        frame
    }
}
