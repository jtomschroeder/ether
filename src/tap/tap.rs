
use std;
use std::io;
use std::mem;
use std::ptr;
use std::time::Duration;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::collections::VecDeque;

use futures;

use libc;
use glob::glob;
use super::bindings::bpf;

struct Config {
    buffer_size: usize,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

fn pselect(
    nfds: &File,
    readfds: Option<&mut libc::fd_set>,
    writefds: Option<&mut libc::fd_set>,
    timeout: Option<Duration>,
) -> io::Result<()> {
    let fd = nfds.as_raw_fd();

    let timeout = timeout.map(|d| {
        libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        }
    });

    let ret = unsafe {
        libc::pselect(
            fd + 1,
            readfds.map(|to| to as *mut libc::fd_set).unwrap_or(
                ptr::null_mut(),
            ),
            writefds.map(|to| to as *mut libc::fd_set).unwrap_or(
                ptr::null_mut(),
            ),
            ptr::null_mut(),
            timeout
                .as_ref()
                .map(|to| to as *const libc::timespec)
                .unwrap_or(ptr::null()),
            ptr::null(),
        )
    };

    match ret {
        -1 => Err(io::Error::last_os_error()), // Error occured!
        0 => Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out")),
        _ => Ok(()),
    }

}

pub struct Tap {
    fd_set: libc::fd_set,
    config: Config,
    file: File,
}

impl Tap {
    pub fn new(interface: &str) -> io::Result<Self> {
        fn open() -> io::Result<File> {
            // On macOS: bpf exposed as /dev/bpf###
            for entry in glob("/dev/bpf*").expect("Failed to read glob pattern") {
                if let Some(file) = entry.ok().and_then(|path| {
                    OpenOptions::new().read(true).write(true).open(&path).ok()
                })
                {
                    return Ok(file);
                }
            }

            Err(io::Error::last_os_error())
        }

        let file = try!(open());
        let config = Config::default();

        {
            let fd = file.as_raw_fd();

            let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
            for (i, c) in interface.bytes().enumerate() {
                iface.ifr_name[i] = c as std::os::raw::c_char;
            }

            // Set the buffer length
            let buflen = config.buffer_size as libc::c_uint;
            ioctl!(fd, bpf::BIOCSBLEN, &buflen);

            // Set the interface to use
            ioctl!(fd, bpf::BIOCSETIF, &iface);

            let yes: libc::c_uint = 1;

            // Return from read as soon as packets are available - don't wait to fill the buffer
            ioctl!(fd, bpf::BIOCIMMEDIATE, &yes);

            // Get the device type
            let mut dlt: libc::c_uint = 0;
            ioctl!(fd, bpf::BIOCGDLT, &mut dlt);

            match dlt {
                bpf::DLT_NULL => {
                    // Allow packets to be read back after they are written
                    ioctl!(fd, bpf::BIOCSSEESENT, &yes);
                }
                _ => {
                    // Don't fill in source MAC
                    ioctl!(fd, bpf::BIOCSHDRCMPLT, &yes);
                }
            }

            /*
            {
                use super::bindings::bpf::*;

                // Allow all!
                let instructions = vec![bpf::BPF_STMT(bpf::BPF_RET + bpf::BPF_K, std::u32::MAX)];

                // Only IPv4/TCP
                // let ethertype_ip = 0x0800;
                // let ipproto_tcp = 6;
                // let instructions = vec![BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
                //                         BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ethertype_ip, 0, 3),
                //                         BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
                //                         BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ipproto_tcp, 0, 1),
                //                         BPF_STMT(BPF_RET + BPF_K, std::u32::MAX),
                //                         BPF_STMT(BPF_RET + BPF_K, 0)];

                ioctl!(
                    fd,
                    BIOCSETF,
                    &bpf_program {
                        bf_len: instructions.len() as u32,
                        bf_insns: instructions.as_ptr(),
                    }
                );
            }
            */

            // Enable nonblocking
            fcntl!(fd, libc::F_SETFL, libc::O_NONBLOCK);
        }

        let mut fd_set: libc::fd_set = unsafe { mem::zeroed() };
        unsafe {
            let fd = file.as_raw_fd();
            let set = &mut fd_set as *mut libc::fd_set;
            libc::FD_ZERO(set);
            libc::FD_SET(fd, set);
        }

        Ok(Tap {
            fd_set: fd_set,
            config: config,
            file: file,
        })
    }

    pub fn stream(&mut self) -> Stream {
        Stream {
            buffer: vec![0u8; self.config.buffer_size],
            packets: VecDeque::new(),
            fd_set: &mut self.fd_set,
            file: &self.file,
            timeout: self.config.read_timeout,
        }
    }

    pub fn sink(&mut self) -> Sink {
        Sink {
            fd_set: &mut self.fd_set,
            file: &self.file,
            timeout: self.config.write_timeout,
        }
    }
}

pub struct Stream<'a> {
    buffer: Vec<u8>,
    packets: VecDeque<(usize, usize)>,
    fd_set: &'a mut libc::fd_set,
    file: &'a File,
    timeout: Option<Duration>,
}

impl<'a> futures::stream::Stream for Stream<'a> {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> futures::Poll<Option<Self::Item>, Self::Error> {
        if self.packets.is_empty() {
            let buffer = &mut self.buffer[..];

            try!(pselect(self.file, Some(self.fd_set), None, self.timeout));

            use std::io::Read;
            let buflen = match self.file.read(buffer) {
                Ok(len) if len > 0 => len,
                _ => return Err(io::Error::last_os_error()),
            };

            let mut ptr = buffer.as_mut_ptr();
            let end = unsafe { buffer.as_ptr().offset(buflen as isize) };
            while (ptr as *const u8) < end {
                unsafe {
                    let packet: *const bpf::bpf_hdr = mem::transmute(ptr);

                    let start = ptr as isize + (*packet).bh_hdrlen as isize -
                        buffer.as_ptr() as isize;
                    self.packets.push_back(
                        (start as usize, (*packet).bh_caplen as usize),
                    );

                    let offset = (*packet).bh_hdrlen as isize + (*packet).bh_caplen as isize;
                    ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                }
            }
        }

        let buffer = &self.buffer[..];
        Ok(
            self.packets
                .pop_front()
                .map(move |(start, len)| Vec::from(&buffer[start..start + len]))
                .into(),
        )
    }
}

pub struct Sink<'a> {
    fd_set: &'a mut libc::fd_set,
    file: &'a File,
    timeout: Option<Duration>,
}

impl<'a> Sink<'a> {
    // Send `packet` on tapped device (packet should contain data starting @ network layer)
    pub fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        use std::io::Write;

        try!(pselect(self.file, None, Some(self.fd_set), self.timeout));
        try!(self.file.write_all(packet));
        Ok(())
    }
}
