
pub mod loopback {
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

                link => panic!("Unsupported link {}", link),
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
}

pub mod ethernet {
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

    #[derive(Debug, PartialEq, Clone)]
    pub enum EtherType {
        IPv4,
        ARP,
        VLAN,
        IPv6,
        Unknown(u16),
    }

    impl From<u16> for EtherType {
        fn from(value: u16) -> Self {
            use self::EtherType::*;
            match value {
                0x0800 => IPv4,
                0x0806 => ARP,
                0x8100 => VLAN, // VLAN-tagged frame (IEEE 802.1Q)
                0x86DD => IPv6,
                e => Unknown(e),
            }
        }
    }

    pub mod vlan {
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

            pub fn ethertype(&self) -> super::EtherType {
                parser::be_u16(&self[2..]).into()
            }

            pub fn payload(&self) -> &[u8] {
                &self[4..]
            }
        }

        impl<'a> fmt::Debug for Frame<'a> {
            fn fmt(&self, fmtr: &mut fmt::Formatter) -> fmt::Result {
                fmtr.debug_struct("vlan::Frame")
                    .field("ethertype", &self.ethertype())
                    .finish()
            }
        }
    }
}
