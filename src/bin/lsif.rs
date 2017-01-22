
//! lsif: list interfaces

extern crate ether;
extern crate libc;

// http://man7.org/linux/man-pages/man3/getifaddrs.3.html
// http://man7.org/linux/man-pages/man7/netdevice.7.html

use std::ffi::CString;

fn main() {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::mem::uninitialized();

        if libc::getifaddrs(&mut ifap) == -1 {
            println!("{:?}", std::io::Error::last_os_error());
            return;
        }

        let mut ifa = ifap;
        while ifa != std::ptr::null_mut() {
            println!("Interface: {:?}", CString::from_raw((*ifa).ifa_name));
            ifa = (*ifa).ifa_next;
        }

        libc::freeifaddrs(ifap);
    }
}
