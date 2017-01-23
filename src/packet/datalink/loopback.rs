
use std::ops;
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

    pub fn link(&self) -> Link {
        let link = &self[..4];
        match parser::le_u32(link) {
            2 => Link::IPv4,
            24 | 28 | 30 => Link::IPv6,

            7 => Link::OSI,
            23 => Link::IPX,

            otherwise => panic!("Unsupported link {}", otherwise),
        }
    }

    pub fn payload(&self) -> &[u8] {
        &self[4..]
    }
}

#[derive(Debug)]
pub enum Link {
    IPv4,
    IPv6,
    OSI,
    IPX,
}
