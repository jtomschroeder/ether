
use nom;
use nom::IResult;

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
pub struct Record<'a> {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
    pub payload: &'a [u8],
}

/// PacketCapture: container for pcap byte-stream
pub struct PacketCapture {
    capture: Vec<u8>,
}

impl PacketCapture {
    pub fn new(capture: Vec<u8>) -> Self {
        PacketCapture { capture: capture }
    }
}

// Parsing

impl Header {
    fn parse(data: &[u8]) -> IResult<&[u8], Header> {
        use nom::*;

        do_parse!(data,
                  magic_number: le_u32 >> version_major: le_u16 >> version_minor: le_u16 >>
                  thiszone: le_i32 >>
                  sigfigs: le_u32 >> snaplen: le_u32 >> network: le_u32 >>
                  (Header {
                      magic_number: magic_number,
                      version_major: version_major,
                      version_minor: version_minor,
                      thiszone: thiszone,
                      sigfigs: sigfigs,
                      snaplen: snaplen,
                      network: Link::from(network),
                  }))
    }
}

impl<'a> Record<'a> {
    fn parse(data: &[u8]) -> IResult<&[u8], Record> {
        use nom::*;

        do_parse!(data,
            ts_sec: le_u32 >>
            ts_usec: le_u32 >>
            incl_len: le_u32 >>
            orig_len: le_u32 >>
            payload: take!(incl_len) >>

            (Record {
                ts_sec: ts_sec,
                ts_usec: ts_usec,
                incl_len: incl_len,
                orig_len: orig_len,
                payload: payload,
            })
        )
    }
}

/// PCAP parse error
#[derive(Debug)]
pub struct ParseError(nom::IError);

impl PacketCapture {
    pub fn parse<'a>(&'a self) -> Result<(Header, Records<'a>), ParseError> {
        match Header::parse(&self.capture) {
            IResult::Done(input, output) => Ok((output, Records { capture: input })),
            IResult::Error(e) => Err(ParseError(nom::IError::Error(e))),
            IResult::Incomplete(i) => Err(ParseError(nom::IError::Incomplete(i))),
        }
    }
}


pub struct Records<'a> {
    capture: &'a [u8],
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match Record::parse(&self.capture) {
            IResult::Done(input, output) => {
                if input.is_empty() {
                    None
                } else {
                    self.capture = input;
                    Some(Ok(output))
                }
            }
            IResult::Error(e) => Some(Err(ParseError(nom::IError::Error(e)))),
            IResult::Incomplete(i) => Some(Err(ParseError(nom::IError::Incomplete(i)))),
        }
    }
}
