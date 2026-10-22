//! One validator's signing history, held in memory and checked against new messages.

use std::collections::BTreeMap;

use axiom_types::{BlsPubkey, Epoch, Root, Slot};

use crate::protection::{
    Refusal,
    surround::{Surround, SurroundIndex},
};

/// Whether a message slashing protection allowed is new or a repeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Safety {
    /// The message is new, and is now recorded.
    Fresh,
    /// The exact message was signed before, so signing it again is harmless.
    Repeat,
}

/// A recorded vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Vote {
    /// Source epoch.
    pub(crate) source: Epoch,
    /// Signing root, unknown for some imported votes.
    pub(crate) root: Option<Root>,
}

/// Every message one validator signed that slashing protection must remember.
///
/// # Overview
///
/// New messages must move forward past everything recorded, signed here or imported.
///
/// - A block's slot must exceed every recorded slot.
/// - A vote's source must reach the highest recorded source.
/// - A vote's target must exceed every recorded target.
///
/// These are EIP-3076's conditions 2, 4, and 5, applied to the whole history.
/// An imported history may be minified, so a gap below its latest message proves nothing.
/// Moving forward is therefore the only safe rule, and honest duties always move forward.
///
/// An exact repeat of a recorded message is allowed: it signs nothing new.
///
/// The records also answer slashability in full, double and surround votes included.
/// Imports are checked that way, since an imported record may sit anywhere.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct History {
    /// Signed blocks by slot, with their signing roots when known.
    pub(crate) blocks: BTreeMap<Slot, Option<Root>>,
    /// Signed votes by target epoch.
    pub(crate) votes: BTreeMap<Epoch, Vote>,
    /// The highest source epoch of any recorded vote.
    latest_source: Option<Epoch>,
    /// The staircases that find surround votes.
    surround: SurroundIndex,
}

impl History {
    /// Whether a block may be signed.
    ///
    /// # Errors
    ///
    /// Refuses a second block at a slot, and a block at or before the latest recorded slot.
    pub(crate) fn check_block(
        &self,
        pubkey: BlsPubkey,
        slot: Slot,
        root: Root,
    ) -> Result<Safety, Refusal> {
        // A repeat is recognized first: re-signing the same block is no proposer slashing.
        if let Some(&recorded) = self.blocks.get(&slot) {
            if recorded == Some(root) {
                return Ok(Safety::Repeat);
            }
            return Err(Refusal::DoubleProposal {
                pubkey,
                slot,
                recorded,
                asked: Some(root),
            });
        }
        if let Some((&latest, _)) = self.blocks.last_key_value()
            && slot <= latest
        {
            return Err(Refusal::BlockNotAfterLatest {
                pubkey,
                slot,
                latest,
            });
        }
        Ok(Safety::Fresh)
    }

    /// Whether a vote may be signed.
    ///
    /// # Errors
    ///
    /// Refuses an inverted vote, a double vote, and a vote that does not move past the history.
    pub(crate) fn check_vote(
        &self,
        pubkey: BlsPubkey,
        source: Epoch,
        target: Epoch,
        root: Root,
    ) -> Result<Safety, Refusal> {
        // A repeat is recognized before the forward rule, as for blocks.
        if self.check_double_vote(pubkey, source, target, Some(root))? == Safety::Repeat {
            return Ok(Safety::Repeat);
        }
        if let Some(latest) = self.latest_source
            && source < latest
        {
            return Err(Refusal::SourceBeforeLatest {
                pubkey,
                source_epoch: source,
                latest,
            });
        }
        if let Some((&latest, _)) = self.votes.last_key_value()
            && target <= latest
        {
            return Err(Refusal::TargetNotAfterLatest {
                pubkey,
                target_epoch: target,
                latest,
            });
        }
        // Invariant: a source at or past every recorded source surrounds nothing.
        // A target past every recorded target is surrounded by nothing.
        // The surround check is then redundant here; it stays as defence in depth.
        self.check_surround(pubkey, source, target)?;
        Ok(Safety::Fresh)
    }

    /// Whether an imported vote is slashable against this history.
    ///
    /// An imported record may sit anywhere in time, so only slashability decides.
    ///
    /// # Errors
    ///
    /// Refuses an inverted vote, a double vote, and a surround vote.
    pub(crate) fn check_imported_vote(
        &self,
        pubkey: BlsPubkey,
        source: Epoch,
        target: Epoch,
        root: Option<Root>,
    ) -> Result<Safety, Refusal> {
        if self.check_double_vote(pubkey, source, target, root)? == Safety::Repeat {
            return Ok(Safety::Repeat);
        }
        self.check_surround(pubkey, source, target)?;
        Ok(Safety::Fresh)
    }

    /// Refuses an inverted vote, and a second vote for a recorded target unless it repeats.
    ///
    /// A vote of unknown root repeats only another vote of unknown root.
    fn check_double_vote(
        &self,
        pubkey: BlsPubkey,
        source: Epoch,
        target: Epoch,
        root: Option<Root>,
    ) -> Result<Safety, Refusal> {
        if source > target {
            return Err(Refusal::SourceAfterTarget {
                pubkey,
                source_epoch: source,
                target_epoch: target,
            });
        }
        match self.votes.get(&target) {
            None => Ok(Safety::Fresh),
            Some(recorded) if recorded.source == source && recorded.root == root => {
                Ok(Safety::Repeat)
            }
            Some(recorded) => Err(Refusal::DoubleVote {
                pubkey,
                target_epoch: target,
                recorded: recorded.root,
                asked: root,
            }),
        }
    }

    /// Refuses a vote that surrounds, or is surrounded by, a recorded vote.
    fn check_surround(
        &self,
        pubkey: BlsPubkey,
        source: Epoch,
        target: Epoch,
    ) -> Result<(), Refusal> {
        match self.surround.find(source, target) {
            None => Ok(()),
            Some(Surround::Surrounded {
                source: recorded_source,
                target: recorded_target,
            }) => Err(Refusal::Surrounded {
                pubkey,
                source_epoch: source,
                target_epoch: target,
                recorded_source,
                recorded_target,
            }),
            Some(Surround::Surrounding {
                source: recorded_source,
                target: recorded_target,
            }) => Err(Refusal::Surrounding {
                pubkey,
                source_epoch: source,
                target_epoch: target,
                recorded_source,
                recorded_target,
            }),
        }
    }

    /// Records a signed block.
    pub(crate) fn record_block(&mut self, slot: Slot, root: Option<Root>) {
        self.blocks.insert(slot, root);
    }

    /// Records a signed vote.
    pub(crate) fn record_vote(&mut self, source: Epoch, target: Epoch, root: Option<Root>) {
        self.votes.insert(target, Vote { source, root });
        self.latest_source = self.latest_source.max(Some(source));
        self.surround.insert(source, target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The validator every test signs for.
    const KEY: BlsPubkey = BlsPubkey([0xaa; 48]);

    #[test]
    fn a_block_must_follow_every_recorded_block() {
        // Fixture state: block 0x01...01 at slot 5, and an import without root at slot 8.
        let mut history = History::default();
        history.record_block(Slot(5), Some(Root([1; 32])));
        history.record_block(Slot(8), None);

        // The same root at slot 5 is a repeat; slot 9 is fresh.
        assert_eq!(
            history.check_block(KEY, Slot(5), Root([1; 32])),
            Ok(Safety::Repeat)
        );
        assert_eq!(
            history.check_block(KEY, Slot(9), Root([3; 32])),
            Ok(Safety::Fresh)
        );

        // Another root at slot 5 is a double proposal.
        assert_eq!(
            history.check_block(KEY, Slot(5), Root([2; 32])),
            Err(Refusal::DoubleProposal {
                pubkey: KEY,
                slot: Slot(5),
                recorded: Some(Root([1; 32])),
                asked: Some(Root([2; 32])),
            })
        );

        // A block of unknown root at slot 8 conflicts with every block there.
        assert_eq!(
            history.check_block(KEY, Slot(8), Root([1; 32])),
            Err(Refusal::DoubleProposal {
                pubkey: KEY,
                slot: Slot(8),
                recorded: None,
                asked: Some(Root([1; 32])),
            })
        );

        // Slot 6 is free, but it lies before the latest block at slot 8.
        assert_eq!(
            history.check_block(KEY, Slot(6), Root([1; 32])),
            Err(Refusal::BlockNotAfterLatest {
                pubkey: KEY,
                slot: Slot(6),
                latest: Slot(8),
            })
        );
    }

    #[test]
    fn a_vote_must_move_past_every_recorded_vote() {
        // Fixture state: a vote from 2 to 6 with root 0x01...01, and one from 4 to 5.
        let mut history = History::default();
        history.record_vote(Epoch(2), Epoch(6), Some(Root([1; 32])));
        history.record_vote(Epoch(4), Epoch(5), None);

        // The same vote is a repeat; 4 to 7 moves forward.
        assert_eq!(
            history.check_vote(KEY, Epoch(2), Epoch(6), Root([1; 32])),
            Ok(Safety::Repeat)
        );
        assert_eq!(
            history.check_vote(KEY, Epoch(4), Epoch(7), Root([2; 32])),
            Ok(Safety::Fresh)
        );

        // Source 7 after target 6 is malformed.
        assert_eq!(
            history.check_vote(KEY, Epoch(7), Epoch(6), Root([1; 32])),
            Err(Refusal::SourceAfterTarget {
                pubkey: KEY,
                source_epoch: Epoch(7),
                target_epoch: Epoch(6),
            })
        );

        // Another root for target 6 is a double vote.
        assert_eq!(
            history.check_vote(KEY, Epoch(4), Epoch(6), Root([2; 32])),
            Err(Refusal::DoubleVote {
                pubkey: KEY,
                target_epoch: Epoch(6),
                recorded: Some(Root([1; 32])),
                asked: Some(Root([2; 32])),
            })
        );

        // Source 3 falls behind the latest source 4.
        assert_eq!(
            history.check_vote(KEY, Epoch(3), Epoch(9), Root([2; 32])),
            Err(Refusal::SourceBeforeLatest {
                pubkey: KEY,
                source_epoch: Epoch(3),
                latest: Epoch(4),
            })
        );

        // Target 4 is free, but it lies before the latest target 6.
        assert_eq!(
            history.check_vote(KEY, Epoch(4), Epoch(4), Root([2; 32])),
            Err(Refusal::TargetNotAfterLatest {
                pubkey: KEY,
                target_epoch: Epoch(4),
                latest: Epoch(6),
            })
        );
    }

    #[test]
    fn an_import_is_judged_by_slashability_alone() {
        // Fixture state: one vote from 2 to 6.
        let mut history = History::default();
        history.record_vote(Epoch(2), Epoch(6), Some(Root([1; 32])));

        // An old vote from 0 to 1 is behind the history but slashable against nothing.
        assert_eq!(
            history.check_imported_vote(KEY, Epoch(0), Epoch(1), None),
            Ok(Safety::Fresh)
        );

        // 3 to 5 sits inside 2 to 6; 1 to 7 contains it.
        assert_eq!(
            history.check_imported_vote(KEY, Epoch(3), Epoch(5), None),
            Err(Refusal::Surrounded {
                pubkey: KEY,
                source_epoch: Epoch(3),
                target_epoch: Epoch(5),
                recorded_source: Epoch(2),
                recorded_target: Epoch(6),
            })
        );
        assert_eq!(
            history.check_imported_vote(KEY, Epoch(1), Epoch(7), None),
            Err(Refusal::Surrounding {
                pubkey: KEY,
                source_epoch: Epoch(1),
                target_epoch: Epoch(7),
                recorded_source: Epoch(2),
                recorded_target: Epoch(6),
            })
        );
    }
}
