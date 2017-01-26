
use libc::*;

// From /usr/include/sys/ioccom.h

// Ioctl's have the command encoded in the lower word, and the size of
// any in or out parameters in the upper word.  The high 3 bits of the
// upper word are used to encode the in/out status of the parameter.
pub const IOCPARM_MASK: c_ulong = 0x1fff; /* parameter length, at most 13 bits */

pub const IOC_VOID: c_ulong = 0x20000000; // no parameters
pub const IOC_OUT: c_ulong = 0x40000000; // copy parameters out
pub const IOC_IN: c_ulong = 0x80000000; // copy parameters in
pub const IOC_INOUT: c_ulong = IOC_IN | IOC_OUT; // copy paramters in and out
pub const IOC_DIRMASK: c_ulong = 0xe0000000; // mask for IN/OUT/VOID

#[macro_export]
macro_rules! ioc {
    ($inout:expr, $group:expr, $num:expr, $len:expr) => (
        $inout | (($len & $crate::ioccom::IOCPARM_MASK) << 16) | (($group) << 8) | ($num)
    )
}

#[macro_export]
macro_rules! io {
    ($g:expr, $n:expr) => (ioc!($crate::ioccom::IOC_VOID, $g as c_ulong, $n, 0))
}

#[macro_export]
macro_rules! ior {
    ($g:expr, $n:expr, $t:expr) => (ioc!($crate::ioccom::IOC_OUT, $g as c_ulong, $n, $t))
}

#[macro_export]
macro_rules! iow {
    ($g:expr, $n:expr, $t:expr) => (ioc!($crate::ioccom::IOC_IN, $g as c_ulong, $n, $t))
}

#[macro_export]
macro_rules! iowr {
    ($g:expr, $n:expr, $t:expr) => (ioc!($crate::ioccom::IOC_INOUT, $g as c_ulong, $n, $t))
}
