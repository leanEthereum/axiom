//! The gate every signature passes: a signing root, cleared by slashing protection.

use std::sync::Arc;

use axiom_types::{BlsPubkey, Preset, Root, phase0::AttestationData};

use crate::{
    protection::{ProtectionError, Refusal, Safety, SlashingDatabase, VoteCheck},
    signing::{Protected, SigningContext, SigningRequest},
};

/// A message cleared for signing, with the root to sign.
///
/// Only the guard creates one, and a signer accepts nothing else.
/// So no path signs a block or a vote that protection has not recorded first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cleared<'a, P: Preset> {
    /// The message.
    request: SigningRequest<'a, P>,
    /// Its signing root.
    root: Root,
    /// What protection said, for a block or a vote.
    safety: Option<Safety>,
}

impl<'a, P: Preset> Cleared<'a, P> {
    /// The message.
    #[must_use]
    pub const fn request(&self) -> &SigningRequest<'a, P> {
        &self.request
    }

    /// The root to sign.
    #[must_use]
    pub const fn root(&self) -> Root {
        self.root
    }

    /// Whether protection recorded the message as new or saw a repeat, for a block or a vote.
    #[must_use]
    pub const fn safety(&self) -> Option<Safety> {
        self.safety
    }
}

/// The signing context and the slashing protection database, which every signature goes through.
#[derive(Clone, Debug)]
pub struct SigningGuard {
    /// The chain signed for.
    context: SigningContext,
    /// The record of every block and vote.
    protection: Arc<SlashingDatabase>,
}

impl SigningGuard {
    /// A guard over a chain and its protection database.
    #[must_use]
    pub const fn new(context: SigningContext, protection: Arc<SlashingDatabase>) -> Self {
        Self {
            context,
            protection,
        }
    }

    /// The chain signed for.
    #[must_use]
    pub const fn context(&self) -> &SigningContext {
        &self.context
    }

    /// The protection database.
    #[must_use]
    pub const fn protection(&self) -> &Arc<SlashingDatabase> {
        &self.protection
    }

    /// Computes a message's signing root and, for a block or a vote, records it durably.
    ///
    /// # Errors
    ///
    /// Fails when protection refuses the message or its store fails.
    pub fn clear<'a, P: Preset>(
        &self,
        pubkey: &BlsPubkey,
        request: SigningRequest<'a, P>,
    ) -> Result<Cleared<'a, P>, ProtectionError> {
        let root = self.context.signing_root(&request);
        let safety = match request.protected() {
            None => None,
            Some(Protected::Block(slot)) => Some(self.protection.check_block(pubkey, slot, root)?),
            Some(Protected::Attestation { source, target }) => {
                Some(self.protection.check_vote(VoteCheck {
                    pubkey: *pubkey,
                    source,
                    target,
                    signing_root: root,
                })?)
            }
        };
        Ok(Cleared {
            request,
            root,
            safety,
        })
    }

    /// Clears many votes in one durable write, each for its key.
    ///
    /// # Errors
    ///
    /// Fails when the store fails, in which case none of the votes may be signed.
    pub fn clear_votes<'a, P: Preset>(
        &self,
        votes: &[(BlsPubkey, &'a AttestationData)],
    ) -> Result<Vec<Result<Cleared<'a, P>, Refusal>>, ProtectionError> {
        let requests: Vec<SigningRequest<'a, P>> = votes
            .iter()
            .map(|(_, data)| SigningRequest::Attestation(data))
            .collect();
        let checks: Vec<VoteCheck> = votes
            .iter()
            .zip(&requests)
            .map(|((pubkey, data), request)| VoteCheck {
                pubkey: *pubkey,
                source: data.source.epoch,
                target: data.target.epoch,
                signing_root: self.context.signing_root(request),
            })
            .collect();
        let outcomes = self.protection.check_votes(&checks)?;
        Ok(requests
            .into_iter()
            .zip(checks)
            .zip(outcomes)
            .map(|((request, check), outcome)| {
                outcome.map(|safety| Cleared {
                    request,
                    root: check.signing_root,
                    safety: Some(safety),
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{
        ChainConfig, Epoch, Minimal, Slot, ValidatorIndex, phase0::BeaconBlockHeader,
    };

    use super::*;

    /// A guard on the minimal chain with validator 0xaa...aa registered.
    fn guard() -> SigningGuard {
        let context = SigningContext::new(Arc::new(ChainConfig::minimal()), Root([1; 32]));
        let protection = SlashingDatabase::in_memory(Root([1; 32])).unwrap();
        protection.register([BlsPubkey([0xaa; 48])]).unwrap();
        SigningGuard::new(context, Arc::new(protection))
    }

    #[test]
    fn a_cleared_block_carries_the_root_protection_recorded() {
        let guard = guard();
        let key = BlsPubkey([0xaa; 48]);
        let header = BeaconBlockHeader {
            slot: Slot(3),
            ..BeaconBlockHeader::default()
        };
        let request = SigningRequest::<Minimal>::Block(&header);

        // The first clearing records the block; its root is the context's signing root.
        let cleared = guard.clear(&key, request).unwrap();
        assert_eq!(cleared.root(), guard.context().signing_root(&request));
        assert_eq!(cleared.safety(), Some(Safety::Fresh));

        // Another block at slot 3 is refused.
        let other = BeaconBlockHeader {
            slot: Slot(3),
            proposer_index: ValidatorIndex(1),
            ..BeaconBlockHeader::default()
        };
        assert!(matches!(
            guard.clear(&key, SigningRequest::<Minimal>::Block(&other)),
            Err(ProtectionError::Refused(_))
        ));
    }

    #[test]
    fn unprotected_messages_skip_the_database() {
        // A randao reveal is no slashable message: it clears with no record, even unregistered.
        let guard = guard();
        let cleared = guard
            .clear(
                &BlsPubkey([0xbb; 48]),
                SigningRequest::<Minimal>::RandaoReveal(Epoch(2)),
            )
            .unwrap();
        assert_eq!(cleared.safety(), None);
    }
}
