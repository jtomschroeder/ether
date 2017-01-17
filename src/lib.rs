
//! This crate provides a library for parsing and manipulating network data, packet captures.
//!
//! # Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! ether = "0.0"
//! ```
//!
//! and this to *root* of your crate:
//!
//! ```rust
//! extern crate ether;
//! ```
//!
//! Here's a simple example that prints all packets received on interface `en0`:
//!
//! ```rust,no_run
//! extern crate futures;
//! extern crate ether;
//!
//! use futures::stream::Stream;
//! use ether::tap;
//!
//! fn main() {
//!     let mut tap = tap::Tap::new("en0").unwrap();
//!     for packet in tap.stream().wait().filter_map(|p| p.ok()) {
//!         println!("{:?}", packet);
//!     }
//! }
//! ```
//!

extern crate num;
extern crate libc;
extern crate glob;
extern crate futures;

#[macro_use]
extern crate nom;

pub mod packet;
pub mod pcap;
pub mod tap;
