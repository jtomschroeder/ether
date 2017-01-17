
pub mod tcp {
    use std::ops;
    use std::fmt;
    use interconnect::parser;

    pub struct Packet<'a>(&'a [u8]);

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

        pub fn sequence(&self) -> u32 {
            parser::be_u32(&self[4..])
        }

        pub fn acknowledgment(&self) -> u32 {
            parser::be_u32(&self[8..])
        }

        pub fn offset(&self) -> u8 {
            (self[12] & 0xF0) >> 4
        }

        pub fn flags(&self) -> Vec<Flag> {
            let mut flags = vec![];

            let bitfield = Bitfield::new(parser::be_u16(&self[12..]) & 0x1FF);
            // println!("{:?}", bitfield);

            use self::Flag::*;

            if bitfield.has(8) {
                flags.push(NS);
            }
            if bitfield.has(7) {
                flags.push(CWR);
            }
            if bitfield.has(6) {
                flags.push(ECE);
            }
            if bitfield.has(5) {
                flags.push(URG);
            }
            if bitfield.has(4) {
                flags.push(ACK);
            }
            if bitfield.has(3) {
                flags.push(PSH);
            }
            if bitfield.has(2) {
                flags.push(RST);
            }
            if bitfield.has(1) {
                flags.push(SYN);
            }
            if bitfield.has(0) {
                flags.push(FIN);
            }

            flags
        }

        pub fn window(&self) -> u16 {
            parser::be_u16(&self[14..])
        }

        pub fn checksum(&self) -> u16 {
            parser::be_u16(&self[16..])
        }

        pub fn urgent(&self) -> u16 {
            parser::be_u16(&self[18..])
        }

        pub fn payload(&self) -> &[u8] {
            let offset = self.offset() as usize * 4;
            &self[offset..]
        }
    }

    impl<'a> fmt::Debug for Packet<'a> {
        fn fmt(&self, fmtr: &mut fmt::Formatter) -> fmt::Result {
            fmtr.debug_struct("tcp::Packet")
                .field("source", &self.source())
                .field("destination", &self.destination())
                .field("sequence", &self.sequence())
                .field("acknowledgment", &self.acknowledgment())
                .field("offset", &self.offset())
                .field("flags", &self.flags())
                .field("window", &self.window())
                .field("checksum", &self.checksum())
                .field("urgent", &self.urgent())
                // Options
                .finish()
        }
    }

    #[allow(dead_code)]
    #[derive(Debug, PartialEq)]
    pub enum Flag {
        NS,
        CWR,
        ECE,
        URG,
        ACK,
        PSH,
        RST,
        SYN,
        FIN,
    }

    #[derive(Debug)]
    struct Bitfield {
        value: u64,
    }

    use num::NumCast;

    impl Bitfield {
        fn new<N: NumCast>(value: N) -> Self {
            Bitfield { value: NumCast::from(value).unwrap() }
        }

        fn has(&self, offset: usize) -> bool {
            let mask = 1 << offset;
            self.value & mask == mask
        }
    }
}
