//! A log file that rotates by size, optionally compressing what it rotates out.

mod access;
mod compression;
mod paths;
mod writer;

pub(super) use writer::RotatingFile;
