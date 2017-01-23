
//! Tap into a network interface to view/inject real-time traffic

#[macro_use]
mod bindings;
mod tap;

pub use self::tap::Tap;
pub use futures::stream::Stream;

pub use self::bindings::bpf;
