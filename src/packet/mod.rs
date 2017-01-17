
mod parser {
    pub fn be_u16(data: &[u8]) -> u16 {
        ((data[0] as u16) << 8) | data[1] as u16
    }

    pub fn be_u32(data: &[u8]) -> u32 {
        ((data[0] as u32) << 24) | ((data[1] as u32) << 16) | ((data[2] as u32) << 8) |
        data[3] as u32
    }

    pub fn le_u32(data: &[u8]) -> u32 {
        ((data[3] as u32) << 24) | ((data[2] as u32) << 16) | ((data[1] as u32) << 8) |
        data[0] as u32
    }
}

pub mod datalink;
pub mod network;
pub mod transport;
