//! The containers Deneb adds or changes: blobs, see EIP-4844.
//!
//! Electra and Fulu keep the payload, its header, and the blob sidecar.

mod blinded_block;
mod blob;
mod block;
mod block_contents;
mod builder;
mod execution;
