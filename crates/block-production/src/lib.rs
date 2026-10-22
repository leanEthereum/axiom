//! Building the block a validator proposes, for every fork, as a pure library.

mod eth1;

pub use eth1::{Eth1Candidate, Eth1Vote};
