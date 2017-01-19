
use num::NumCast;

#[derive(Debug)]
pub struct Bitfield {
    value: u64,
}

impl Bitfield {
    pub fn new<N: NumCast>(value: N) -> Self {
        Bitfield { value: NumCast::from(value).unwrap() }
    }

    pub fn has(&self, offset: usize) -> bool {
        let mask = 1 << offset;
        self.value & mask == mask
    }
}
