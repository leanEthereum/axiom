//! Peer data availability sampling: who custodies which columns, and when a column is valid.
//!
//! # Overview
//!
//! Each blob is extended to twice its size with a Reed-Solomon code, then cut into cells.
//! The cells of all blobs form a matrix whose columns are gossiped separately.
//!
//! ```text
//!            column 0   column 1   ...   column 127
//! blob 0     cell       cell             cell
//! blob 1     cell       cell             cell
//! ```
//!
//! A node custodies a few columns and samples a few more.
//! Any half of a row recovers the whole row, so sampled availability implies full availability.
//!
//! See EIP-7594 and the Fulu `das-core.md` and `p2p-interface.md` specs.

mod column;
mod custody;

pub use column::{ColumnError, ColumnSidecar};
pub use custody::{CustodyError, CustodyGroup, NodeId};
