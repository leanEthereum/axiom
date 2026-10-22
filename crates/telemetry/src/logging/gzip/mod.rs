//! Gzip compression of rotated log files, written without a compression library.
//!
//! Source: RFC 1951 for deflate, and RFC 1952 for the gzip member around it.

mod bits;
mod crc32;
mod deflate;
mod matcher;
mod member;
mod tables;

pub(super) use member::GzipWriter;
#[cfg(test)]
pub(super) use member::tests::gunzip;
