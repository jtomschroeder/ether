
use std::ops;
use std::fmt;
use std::net::Ipv4Addr;

use utility::parser;

pub struct Packet<'a>(&'a [u8]);

#[doc(hidden)]
impl<'a> ops::Deref for Packet<'a> {
    type Target = &'a [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> Packet<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Packet(data)
    }

    pub fn ihl(&self) -> u8 {
        self[0] & 0xF
    }

    pub fn length(&self) -> u16 {
        parser::be_u16(&self[2..])
    }

    pub fn protocol(&self) -> Protocol {
        self[9].into()
    }

    pub fn source(&self) -> Ipv4Addr {
        let addr = &self[12..16];
        Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])
    }

    pub fn destination(&self) -> Ipv4Addr {
        let addr = &self[16..20];
        Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])
    }

    pub fn payload(&self) -> &[u8] {
        let offset = self.ihl() as usize * 4;
        let end = self.length() as usize;
        &self[offset..end]
    }
}

impl<'a> fmt::Debug for Packet<'a> {
    fn fmt(&self, fmtr: &mut fmt::Formatter) -> fmt::Result {
        fmtr.debug_struct("ipv4::Packet")
            // Version
            .field("ihl", &self.ihl())
            // DSCP
            // ECN
            .field("length", &self.length())
            // Identification
            // Flags
            // Fragment Offset
            // Time To Live
            .field("protocol", &self.protocol())
            // Header Checksum
            .field("source", &self.source())
            .field("destination", &self.destination())
            // Options
            // .field("payload", &self.payload())
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub enum Protocol {
    ICMP,
    IGMP,
    TCP,
    UDP,
    ENCAP,
    OSPF,
    SCTP,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        use self::Protocol::*;
        match value {
            1 => ICMP,
            2 => IGMP,
            6 => TCP,
            17 => UDP,
            41 => ENCAP,
            89 => OSPF,
            132 => SCTP,
            otherwise => Unknown(otherwise),
        }
    }
}
