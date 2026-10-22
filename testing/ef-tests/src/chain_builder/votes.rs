//! The votes a block carries: attestations and the sync committee's signature.

use std::collections::HashMap;

use axiom_ssz::{BitList, Length, ProgressiveBitList};
use axiom_state_transition::{EpochCommittees, State};
use axiom_types::{
    BlsSignature, CommitteeIndex, Preset, Slot, ValidatorIndex,
    accessors::CoreState,
    altair::{SyncAggregate, SyncCommitteeBits},
    constants::{DOMAIN_BEACON_ATTESTER, DOMAIN_SYNC_COMMITTEE, G2_POINT_AT_INFINITY},
    electra, gloas,
    phase0::{self, AttestationData, SigningData},
    vote::{CommitteeVote, PayloadClaim},
};

use crate::chain_builder::{ChainBuilderError, keyring::Keyring};

/// Who signs the votes the blocks carry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Participation {
    /// No one votes: blocks carry no attestations and an empty sync aggregate.
    #[default]
    Silent,
    /// Every sync committee seat signs, but no one attests.
    ///
    /// Blocks then feed light clients while adding no fork choice weight.
    SyncOnly,
    /// Every committee member attests the previous slot, and every sync committee seat signs.
    Full,
}

/// One committee's vote on the previous slot, signed by all its members.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SignedCommittee {
    /// The vote.
    data: AttestationData,
    /// Members of the committee.
    size: usize,
    /// Aggregate signature of every member.
    signature: BlsSignature,
}

/// Every committee's vote on the previous slot, in both shapes forks carry it.
///
/// Before Electra, each committee's vote names its committee and travels alone.
/// From Electra on, one attestation aggregates every committee, and its data names none.
/// Both forms are signed here; the block's fork picks one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommitteeVotes {
    /// Each committee's own vote, as phase0 to Deneb carry them.
    committees: Vec<SignedCommittee>,
    /// The vote of every committee at once, as Electra on carries it.
    aggregate: SignedCommittee,
}

/// What the validators sign for the block of a slot.
///
/// The block at slot s carries the attestations of slot s - 1, the earliest inclusion allowed.
/// Each votes for the latest block at s - 1, its epoch boundary block, and the justified checkpoint.
///
/// See `get_attestation_signature` in the phase0 validator spec.
/// See `get_sync_committee_message` in the Altair validator spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Votes {
    /// The committees' votes, when validators attest.
    attestations: Option<CommitteeVotes>,
    /// The sync committee's signature over the previous slot's block, when it signs.
    sync_signature: Option<BlsSignature>,
}

impl Votes {
    /// The votes for the block of the slot a state was advanced to.
    ///
    /// # Errors
    ///
    /// Fails at slot zero, when a voted root is out of reach, or when a signer has no key.
    pub(crate) fn new<P: Preset>(
        state: &State<P>,
        keyring: &Keyring,
        participation: Participation,
    ) -> Result<Self, ChainBuilderError> {
        let slot = state.beacon().slot();
        let voted = Slot(
            slot.0
                .checked_sub(1)
                .ok_or(ChainBuilderError::NoBlockRoot(slot))?,
        );
        Ok(match participation {
            Participation::Silent => Self::default(),
            Participation::SyncOnly => Self {
                attestations: None,
                sync_signature: CommitteeVotes::sync_signature(state, voted, keyring)?,
            },
            Participation::Full => Self {
                attestations: Some(CommitteeVotes::new(state, voted, keyring)?),
                sync_signature: CommitteeVotes::sync_signature(state, voted, keyring)?,
            },
        })
    }

    /// Each committee's vote on a slot, as a committee vote that travels alone.
    ///
    /// A vote of the voted block's own slot claims nothing about its payload.
    ///
    /// # Errors
    ///
    /// Fails when the state is not past the slot, or a voted root is out of reach.
    pub(crate) fn committee_votes<P: Preset>(
        state: &State<P>,
        voted: Slot,
        keyring: &Keyring,
    ) -> Result<Vec<CommitteeVote>, ChainBuilderError> {
        let votes = CommitteeVotes::new(state, voted, keyring)?;
        Ok(votes
            .committees
            .into_iter()
            .map(|committee| CommitteeVote {
                committees: vec![committee.data.index],
                bits: vec![true; committee.size],
                data: committee.data,
                signature: committee.signature,
                payload: PayloadClaim::Silent,
            })
            .collect())
    }

    /// One attestation per committee, as phase0 to Deneb blocks carry them.
    ///
    /// # Errors
    ///
    /// Fails when a committee outgrows an attestation's bits.
    pub(crate) fn phase0_attestations<P: Preset>(
        &self,
    ) -> Result<Vec<phase0::Attestation<P>>, ChainBuilderError> {
        let committees = self.attestations.iter().flat_map(|votes| &votes.committees);
        committees
            .map(|committee| {
                Ok(phase0::Attestation {
                    aggregation_bits: all_set(committee.size)?,
                    data: committee.data.clone(),
                    signature: committee.signature,
                })
            })
            .collect()
    }

    /// One attestation for every committee, as Electra and Fulu blocks carry it.
    ///
    /// # Errors
    ///
    /// Fails when the committees outgrow an attestation's bits.
    pub(crate) fn electra_attestations<P: Preset>(
        &self,
    ) -> Result<Vec<electra::Attestation<P>>, ChainBuilderError> {
        self.attestations
            .iter()
            .map(|votes| {
                Ok(electra::Attestation {
                    aggregation_bits: all_set(votes.aggregate.size)?,
                    data: votes.aggregate.data.clone(),
                    signature: votes.aggregate.signature,
                    committee_bits: votes.committee_bits::<P>(),
                })
            })
            .collect()
    }

    /// One attestation for every committee, with the unbounded bits of Gloas.
    ///
    /// The data index is zero: the voted block is of the voted slot, so no payload is claimed.
    /// See `process_attestation` in the Gloas beacon chain spec.
    pub(crate) fn gloas_attestations<P: Preset>(&self) -> Vec<gloas::Attestation<P>> {
        self.attestations
            .iter()
            .map(|votes| {
                let mut aggregation_bits = ProgressiveBitList::with_len(votes.aggregate.size);
                for index in 0..votes.aggregate.size {
                    aggregation_bits.set(index, true);
                }
                gloas::Attestation {
                    aggregation_bits,
                    data: votes.aggregate.data.clone(),
                    signature: votes.aggregate.signature,
                    committee_bits: votes.committee_bits::<P>(),
                }
            })
            .collect()
    }

    /// The sync aggregate with every seat signing, or an empty one.
    ///
    /// The point at infinity is the valid signature of an empty aggregate.
    /// See `eth_fast_aggregate_verify` in the Altair BLS spec.
    pub(crate) fn sync_aggregate<P: Preset>(&self) -> SyncAggregate<P> {
        let mut sync_committee_bits = SyncCommitteeBits::<P>::default();
        let Some(signature) = self.sync_signature else {
            return SyncAggregate {
                sync_committee_bits,
                sync_committee_signature: G2_POINT_AT_INFINITY,
            };
        };
        for seat in 0..P::SYNC_COMMITTEE_SIZE {
            sync_committee_bits.set(seat as usize, true);
        }
        SyncAggregate {
            sync_committee_bits,
            sync_committee_signature: signature,
        }
    }
}

impl CommitteeVotes {
    /// Every committee's vote on a slot, signed by all its members.
    fn new<P: Preset>(
        state: &State<P>,
        voted: Slot,
        keyring: &Keyring,
    ) -> Result<Self, ChainBuilderError> {
        let beacon = state.beacon();
        let epoch = voted.epoch::<P>();
        let missing = || ChainBuilderError::NoBlockRoot(voted);

        // A vote from the previous epoch builds on the previous justified checkpoint.
        // See the source check of `process_attestation` in the phase0 beacon chain spec.
        let source = if epoch == beacon.current_epoch() {
            beacon.current_justified_checkpoint()
        } else {
            beacon.previous_justified_checkpoint()
        };
        let data = AttestationData {
            slot: voted,
            index: CommitteeIndex(0),
            beacon_block_root: beacon.block_root_at_slot(voted).ok_or_else(missing)?,
            source,
            target: phase0::Checkpoint {
                epoch,
                root: beacon.block_root(epoch).ok_or_else(missing)?,
            },
        };
        let domain = beacon.domain(DOMAIN_BEACON_ATTESTER, epoch);

        let shuffling = EpochCommittees::compute(beacon, epoch);
        let members: Vec<&[ValidatorIndex]> = (0..shuffling.committees_per_slot())
            .filter_map(|index| shuffling.committee(voted, CommitteeIndex(index)))
            .collect();
        let mut committees = Vec::with_capacity(members.len());
        for (index, committee) in (0..).zip(&members) {
            let data = AttestationData {
                index: CommitteeIndex(index),
                ..data.clone()
            };
            let signing_root = SigningData::signing_root(&data, domain);
            committees.push(SignedCommittee {
                signature: keyring.sign_together(committee, signing_root)?,
                size: committee.len(),
                data,
            });
        }
        let everyone: Vec<ValidatorIndex> = members.concat();
        let signing_root = SigningData::signing_root(&data, domain);
        let aggregate = SignedCommittee {
            signature: keyring.sign_together(&everyone, signing_root)?,
            size: everyone.len(),
            data,
        };
        Ok(Self {
            committees,
            aggregate,
        })
    }

    /// Every seat's signature over the root of the latest block at a slot, from Altair on.
    fn sync_signature<P: Preset>(
        state: &State<P>,
        voted: Slot,
        keyring: &Keyring,
    ) -> Result<Option<BlsSignature>, ChainBuilderError> {
        let beacon = state.beacon();
        let Some(sync) = beacon.sync_committees() else {
            return Ok(None);
        };
        let indices: HashMap<_, _> = beacon
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| (validator.pubkey, ValidatorIndex(index as u64)))
            .collect();
        let mut seats = Vec::new();
        for (seat, key) in sync.current_sync_committee().pubkeys.iter().enumerate() {
            let index = indices
                .get(key)
                .ok_or(ChainBuilderError::UnknownSyncMember { seat })?;
            seats.push(*index);
        }
        let root = beacon
            .block_root_at_slot(voted)
            .ok_or(ChainBuilderError::NoBlockRoot(voted))?;
        let domain = beacon.domain(DOMAIN_SYNC_COMMITTEE, voted.epoch::<P>());
        keyring
            .sign_together(&seats, SigningData::signing_root(&root, domain))
            .map(Some)
    }

    /// One bit for each committee of the voted slot.
    fn committee_bits<P: Preset>(&self) -> electra::CommitteeBits<P> {
        let mut committee_bits = electra::CommitteeBits::<P>::default();
        for index in 0..self.committees.len() {
            committee_bits.set(index, true);
        }
        committee_bits
    }
}

/// A bit list of a length with every bit set.
fn all_set<N: Length>(len: usize) -> Result<BitList<N>, ChainBuilderError> {
    let mut bits = BitList::with_len(len).map_err(|_| ChainBuilderError::TooManyAttesters {
        count: len,
        limit: N::LEN,
    })?;
    for index in 0..len {
        bits.set(index, true);
    }
    Ok(bits)
}
