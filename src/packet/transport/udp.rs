
use std::ops;
use std::fmt;
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

    pub fn source(&self) -> u16 {
        parser::be_u16(&self[..])
    }

    pub fn destination(&self) -> u16 {
        parser::be_u16(&self[2..])
    }

    pub fn length(&self) -> u16 {
        parser::be_u16(&self[4..])
    }

    pub fn checksum(&self) -> u16 {
        parser::be_u16(&self[6..])
    }

    pub fn payload(&self) -> &[u8] {
        let length = self.length() as usize;
        &self[8..length]
    }
}

impl<'a> fmt::Debug for Packet<'a> {
    fn fmt(&self, fmtr: &mut fmt::Formatter) -> fmt::Result {
        fmtr.debug_struct("udp::Packet")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("length", &self.length())
            .field("checksum", &self.checksum())
            .finish()
    }
}
