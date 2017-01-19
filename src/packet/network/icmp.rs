
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

// struct Builder {
//     class: u8,
//     code: u8,
//     identifier: u16,
//     sequence: u16,
//     payload: Vec<u8>,
// }

impl<'a> Packet<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Packet(data)
    }

    /// i.e. ICMP 'type'
    pub fn class(&self) -> u8 {
        self[0]
    }

    pub fn code(&self) -> u8 {
        self[1]
    }

    pub fn checksum(&self) -> u16 {
        parser::be_u16(&self[2..])
    }

    pub fn identifier(&self) -> u16 {
        parser::be_u16(&self[4..])
    }

    pub fn sequence(&self) -> u16 {
        parser::be_u16(&self[6..])
    }

    pub fn payload(&self) -> &[u8] {
        &self[8..]
    }
}

impl<'a> fmt::Debug for Packet<'a> {
    fn fmt(&self, fmtr: &mut fmt::Formatter) -> fmt::Result {
        fmtr.debug_struct("icmp::Packet")
            .field("class", &self.class())
            .field("code", &self.code())
            .field("checksum", &self.checksum())
            .field("identifier", &self.identifier())
            .field("sequence", &self.sequence())
            .field("payload", &self.payload())
            .finish()
    }
}
