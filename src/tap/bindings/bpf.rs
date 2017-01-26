
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use libc::{self, c_ulong, c_char, c_uchar, c_int, c_uint, c_ushort};

// From /usr/include/net/if.h

const IF_NAMESIZE: usize = 16;
const IFNAMSIZ: usize = IF_NAMESIZE;

pub struct ifreq {
    pub ifr_name: [c_char; IFNAMSIZ],
    pub ifru_addr: libc::sockaddr, // NOTE: should be a `union`
}

// From /usr/include/net/bpf.h

pub struct bpf_program {
    pub bf_len: c_uint,
    pub bf_insns: *const bpf_insn,
}

pub struct bpf_insn {
    code: c_ushort,
    jt: c_uchar,
    jf: c_uchar,
    k: libc::uint32_t,
}

pub fn BPF_STMT(code: c_ushort, k: libc::uint32_t) -> bpf_insn {
    bpf_insn {
        code: code,
        jt: 0,
        jf: 0,
        k: k,
    }
}

pub fn BPF_JUMP(code: c_ushort, k: libc::uint32_t, jt: c_uchar, jf: c_uchar) -> bpf_insn {
    bpf_insn {
        code: code,
        jt: jt,
        jf: jf,
        k: k,
    }
}

// The instruction encodings.

// instruction classes
pub const BPF_LD: c_ushort = 0x00;
pub const BPF_LDX: c_ushort = 0x01;
pub const BPF_ST: c_ushort = 0x02;
pub const BPF_STX: c_ushort = 0x03;
pub const BPF_ALU: c_ushort = 0x04;
pub const BPF_JMP: c_ushort = 0x05;
pub const BPF_RET: c_ushort = 0x06;
pub const BPF_MISC: c_ushort = 0x07;
// ld/ldx fields
pub const BPF_W: c_ushort = 0x00;
pub const BPF_H: c_ushort = 0x08;
pub const BPF_B: c_ushort = 0x10;
pub const BPF_IMM: c_ushort = 0x00;
pub const BPF_ABS: c_ushort = 0x20;
pub const BPF_IND: c_ushort = 0x40;
pub const BPF_MEM: c_ushort = 0x60;
pub const BPF_LEN: c_ushort = 0x80;
pub const BPF_MSH: c_ushort = 0xa0;
// alu fields
pub const BPF_ADD: c_ushort = 0x00;
pub const BPF_SUB: c_ushort = 0x10;
pub const BPF_MUL: c_ushort = 0x20;
pub const BPF_DIV: c_ushort = 0x30;
pub const BPF_OR: c_ushort = 0x40;
pub const BPF_AND: c_ushort = 0x50;
pub const BPF_LSH: c_ushort = 0x60;
pub const BPF_RSH: c_ushort = 0x70;
pub const BPF_NEG: c_ushort = 0x80;
// jmp fields
pub const BPF_JA: c_ushort = 0x00;
pub const BPF_JEQ: c_ushort = 0x10;
pub const BPF_JGT: c_ushort = 0x20;
pub const BPF_JGE: c_ushort = 0x30;
pub const BPF_JSET: c_ushort = 0x40;
pub const BPF_K: c_ushort = 0x00;
pub const BPF_X: c_ushort = 0x08;
// ret - BPF_K and BPF_X also apply
pub const BPF_A: c_ushort = 0x10;
// misc
pub const BPF_TAX: c_ushort = 0x00;
pub const BPF_TXA: c_ushort = 0x80;

struct bpf_stat {
    bs_recv: c_uint, // number of packets received
    bs_drop: c_uint, // number of packets dropped
}

struct bpf_version {
    bv_major: c_ushort,
    bv_minor: c_ushort,
}

const SIZEOF_TIMEVAL: c_ulong = 16;
const SIZEOF_IFREQ: c_ulong = 32;
const SIZEOF_UINT: c_ulong = 4;
const SIZEOF_INT32: c_ulong = 4;
const SIZEOF_BPF_PROGRAM: c_ulong = 16;

pub const BIOCGBLEN: c_ulong = ior!('B', 102, SIZEOF_UINT);
pub const BIOCSBLEN: c_ulong = iowr!('B', 102, SIZEOF_UINT);
pub const BIOCSETF: c_ulong = iow!('B', 103, SIZEOF_BPF_PROGRAM);
pub const BIOCFLUSH: c_ulong = io!('B', 104);
pub const BIOCPROMISC: c_ulong = io!('B', 105);
pub const BIOCGDLT: c_ulong = ior!('B', 106, SIZEOF_UINT);
pub const BIOCGETIF: c_ulong = ior!('B', 107, SIZEOF_IFREQ);
pub const BIOCSETIF: c_ulong = iow!('B', 108, SIZEOF_IFREQ);
pub const BIOCSRTIMEOUT: c_ulong = iow!('B', 109, SIZEOF_TIMEVAL);
pub const BIOCGRTIMEOUT: c_ulong = ior!('B', 110, SIZEOF_TIMEVAL);
// pub const BIOCGSTATS: c_ulong = ior!('B', 111, struct bpf_stat);
pub const BIOCIMMEDIATE: c_ulong = iow!('B', 112, SIZEOF_UINT);
// pub const BIOCVERSION: c_ulong = ior!('B', 113, struct bpf_version);
pub const BIOCGRSIG: c_ulong = ior!('B', 114, SIZEOF_UINT);
pub const BIOCSRSIG: c_ulong = iow!('B', 115, SIZEOF_UINT);
pub const BIOCGHDRCMPLT: c_ulong = ior!('B', 116, SIZEOF_UINT);
pub const BIOCSHDRCMPLT: c_ulong = iow!('B', 117, SIZEOF_UINT);
pub const BIOCGSEESENT: c_ulong = ior!('B', 118, SIZEOF_UINT);
pub const BIOCSSEESENT: c_ulong = iow!('B', 119, SIZEOF_UINT);
pub const BIOCSDLT: c_ulong = iow!('B', 120, SIZEOF_UINT);
// pub const BIOCGDLTLIST: c_ulong = iowr!('B', 121, struct bpf_dltlist);
pub const BIOCSETFNR: c_ulong = iow!('B', 126, SIZEOF_BPF_PROGRAM);

// Device Type
pub const DLT_NULL: c_uint = 0; // BSD loopback encapsulation
pub const DLT_EN10MB: c_uint = 1; // Ethernet (10Mb)
pub const DLT_EN3MB: c_uint = 2; // Experimental Ethernet (3Mb)
pub const DLT_AX25: c_uint = 3; // Amateur Radio AX.25
pub const DLT_PRONET: c_uint = 4; // Proteon ProNET Token Ring
pub const DLT_CHAOS: c_uint = 5; // Chaos
pub const DLT_IEEE802: c_uint = 6; // 802.5 Token Ring
pub const DLT_ARCNET: c_uint = 7; // ARCNET, with BSD-style header
pub const DLT_SLIP: c_uint = 8; // Serial Line IP
pub const DLT_PPP: c_uint = 9; // Point-to-point Protocol
pub const DLT_FDDI: c_uint = 10; // FDDI

const BPF_ALIGNMENT: c_ulong = SIZEOF_INT32;

pub fn BPF_WORDALIGN(x: isize) -> isize {
    let alignment = BPF_ALIGNMENT as isize - 1;
    (x + alignment) & !alignment
}

#[cfg(target_pointer_width = "32")]
type bh_timeval = libc::timeval;

#[cfg(target_pointer_width = "64")]
pub struct bh_timeval {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

pub struct bpf_hdr {
    pub bh_tstamp: bh_timeval,
    pub bh_caplen: u32,
    pub bh_datalen: u32,
    pub bh_hdrlen: c_ushort,
}
