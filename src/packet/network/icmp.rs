
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
            .field("payload.len()", &self.payload().len())
            .finish()
    }
}

pub struct Builder {
    class: u8,
    code: u8,
    // checksum: u16,
    identifier: u16,
    sequence: u16,
}

fn nibbles(num: u16) -> (u8, u8) {
    ((num >> 8) as u8, (num & 0xFF) as u8)
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            class: 8,
            code: 0,
            // checksum: 0,
            identifier: 51123,
            sequence: 1,
        }
    }

    pub fn build(&self, payload: &[u8]) -> Vec<u8> {
        let id = nibbles(self.identifier);
        let seq = nibbles(self.sequence);

        let mut frame = vec![self.class, self.code, 0, 0, id.0, id.1, seq.0, seq.1];
        frame.extend(payload);

        let checksum = nibbles(checksum(&frame, 1));
        frame[2] = checksum.0;
        frame[3] = checksum.1;

        frame
    }
}

// ------

use std::slice;

/// Calculates a checksum. Used by ipv4 and icmp. The two bytes starting at `skipword * 2` will be
/// ignored. Supposed to be the checksum field, which is regarded as zero during calculation.
pub fn checksum(data: &[u8], skipword: usize) -> u16 {
    let sum = sum_be_words(data, skipword);
    finalize_checksum(sum)
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

/// Sum all words (16 bit chunks) in the given data. The word at word offset
/// `skipword` will be skipped. Each word is treated as big endian.
fn sum_be_words(data: &[u8], skipword: usize) -> u32 {
    let len = data.len();
    let wdata: &[u16] = unsafe { slice::from_raw_parts(data.as_ptr() as *const u16, len / 2) };
    assert!(skipword <= wdata.len());

    let mut sum = 0u32;
    let mut i = 0;
    while i < skipword {
        sum += u16::from_be(unsafe { *wdata.get_unchecked(i) }) as u32;
        i += 1;
    }
    i += 1;
    while i < wdata.len() {
        sum += u16::from_be(unsafe { *wdata.get_unchecked(i) }) as u32;
        i += 1;
    }
    // If the length is odd, make sure to checksum the final byte
    if len & 1 != 0 {
        sum += (unsafe { *data.get_unchecked(len - 1) } as u32) << 8;
    }

    sum
}
