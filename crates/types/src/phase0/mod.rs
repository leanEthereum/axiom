//! The containers of phase0, the launch of the beacon chain.
//!
//! Every later fork starts from this set and replaces what its spec modifies.
//! See the phase0 beacon chain, validator, and networking specs.

mod aggregate;
mod attestation;
mod block;
mod block_header;
mod checkpoint;
mod deposit;
mod eth1;
mod exit;
mod fork;
mod historical;
mod signing;
mod slashing;
mod state;
mod validator;

pub use aggregate::{AggregateAndProof, SignedAggregateAndProof};
pub use attestation::{
    AggregationBits, Attestation, AttestationData, AttestingIndices, IndexedAttestation,
    PendingAttestation,
};
pub use block::{BeaconBlock, BeaconBlockBody, SignedBeaconBlock};
pub use block_header::{BeaconBlockHeader, SignedBeaconBlockHeader};
pub use checkpoint::Checkpoint;
pub use deposit::{Deposit, DepositData, DepositMessage, DepositProof};
pub use eth1::{Eth1Block, Eth1Data};
pub use exit::{SignedVoluntaryExit, VoluntaryExit};
pub use fork::{Fork, ForkData};
pub use historical::HistoricalBatch;
pub use signing::SigningData;
pub use slashing::{AttesterSlashing, ProposerSlashing};
pub use state::{
    Balances, BeaconState, BlockRoots, Eth1DataVotes, HistoricalRoots, JustificationBits,
    PendingAttestations, RandaoMixes, Slashings, StateRoots, Validators,
};
pub use validator::Validator;
