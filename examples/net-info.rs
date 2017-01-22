
extern crate ether;
extern crate libc;

//  fn getnameinfo(sa: *const sockaddr,
//                 salen: socklen_t,
//                 host: *mut c_char,
//                 hostlen: socklen_t,
//                 serv: *mut c_char,
//                 sevlen: socklen_t,
//                 flags: c_int)
//                 -> c_int;

use std::ffi::CString;

fn main() {
    let node = CString::new("www.google.com").unwrap();
    let service = CString::new("http").unwrap();

    // TODO: provide `hints`

    unsafe {
        let mut res: *mut libc::addrinfo = std::mem::uninitialized();

        if libc::getaddrinfo(node.as_ptr(), service.as_ptr(), std::ptr::null(), &mut res) == -1 {
            println!("{:?}", std::io::Error::last_os_error());
            return;
        }

        let mut p = res;
        while p != std::ptr::null_mut() {
            let addr = std::mem::transmute::<*const libc::sockaddr,
                                             *const libc::sockaddr_in>((*p).ai_addr);

            let bits = u32::from_be((*addr).sin_addr.s_addr);
            let octets = [(bits >> 24) as u8, (bits >> 16) as u8, (bits >> 8) as u8, bits as u8];

            let addr = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            println!("{:?} {:?}", (*p).ai_socktype, addr);

            p = (*p).ai_next;
        }

        libc::freeaddrinfo(res);
    }
}
