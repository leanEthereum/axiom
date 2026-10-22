//! The proof-of-work blocks a node knows, and the terminal block check of the merge.

use std::collections::HashMap;

use axiom_types::{ChainConfig, Hash32, Preset, Slot, bellatrix::PowBlock};

use crate::ForkChoiceError;

/// Slots a merge block must age before it may import with its payload unvalidated.
///
/// The delay leaves the honest chain time to justify past a merge block built on junk.
/// The optimistic sync spec asks for it to be configurable; this client fixes it at the spec's value.
/// See `SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY` in the Bellatrix optimistic sync spec.
pub const SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY: u64 = 128;

/// The proof-of-work blocks the execution layer reported, by hash.
///
/// The spec models them as a lookup into the execution client.
/// The store keeps the answers instead, so it stays a pure function of its inputs.
/// See `get_pow_block` in the Bellatrix fork choice spec.
#[derive(Clone, Debug, Default)]
pub struct PowChain {
    /// Known blocks by hash.
    blocks: HashMap<Hash32, PowBlock>,
}

impl PowChain {
    /// Records a proof-of-work block.
    pub fn insert(&mut self, block: PowBlock) {
        self.blocks.insert(block.block_hash, block);
    }

    /// Checks that a merge transition block builds on a valid terminal proof-of-work block.
    ///
    /// # Algorithm
    ///
    /// 1. A hand-fixed terminal block hash, when configured, must be the payload's parent.
    /// 2. Otherwise the payload's parent and its own parent must both be known.
    /// 3. The parent must reach the terminal total difficulty, and its own parent must not.
    ///
    /// The third step pins the merge to the first block past the threshold.
    /// See `validate_merge_block` and `is_valid_terminal_pow_block` in the Bellatrix fork choice spec.
    ///
    /// # Errors
    ///
    /// Fails when a block is unknown, or the parent is not the terminal block.
    pub fn validate_merge_block<P: Preset>(
        &self,
        config: &ChainConfig,
        slot: Slot,
        parent_hash: Hash32,
    ) -> Result<(), ForkChoiceError> {
        if config.terminal_block_hash != Hash32::ZERO {
            let epoch = slot.epoch::<P>();
            let activation = config.terminal_block_hash_activation_epoch;
            if epoch < activation {
                return Err(ForkChoiceError::TerminalBlockTooEarly { epoch, activation });
            }
            if parent_hash != config.terminal_block_hash {
                return Err(ForkChoiceError::NotTerminalBlockHash {
                    parent_hash,
                    terminal: config.terminal_block_hash,
                });
            }
            return Ok(());
        }

        let block = self
            .blocks
            .get(&parent_hash)
            .ok_or(ForkChoiceError::UnknownPowBlock(parent_hash))?;
        let parent = self
            .blocks
            .get(&block.parent_hash)
            .ok_or(ForkChoiceError::UnknownPowBlock(block.parent_hash))?;
        let threshold = config.terminal_total_difficulty;
        // Threshold: the terminal block reaches it, and is the first on its chain to do so.
        if block.total_difficulty < threshold || parent.total_difficulty >= threshold {
            return Err(ForkChoiceError::NotTerminalPowBlock(parent_hash));
        }
        Ok(())
    }

    /// Checks a merge block whose payload the engine has not validated yet.
    ///
    /// # Algorithm
    ///
    /// 1. The block must be at least the safe slot count older than the clock.
    /// 2. A terminal block the engine does not know yet passes: the engine may still be syncing.
    /// 3. Every other check runs as for a validated payload, the hand-fixed hash included.
    ///
    /// A known parent whose own parent is unknown still fails, as the spec only excuses both unknown.
    /// See "How to optimistically import blocks" in the Bellatrix optimistic sync spec.
    ///
    /// # Errors
    ///
    /// Fails when the block is too recent, or a known block is not the terminal block.
    pub fn validate_optimistic_merge_block<P: Preset>(
        &self,
        config: &ChainConfig,
        slot: Slot,
        current_slot: Slot,
        parent_hash: Hash32,
    ) -> Result<(), ForkChoiceError> {
        // Fork choice poisoning: only an old merge block may skip the terminal block check.
        if current_slot.0.saturating_sub(slot.0) < SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY {
            return Err(ForkChoiceError::OptimisticMergeTooRecent {
                slot,
                current_slot,
                safe_slots: SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
            });
        }
        let overridden = config.terminal_block_hash != Hash32::ZERO;
        if !overridden && !self.blocks.contains_key(&parent_hash) {
            return Ok(());
        }
        self.validate_merge_block::<P>(config, slot, parent_hash)
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::U256;
    use axiom_types::{Epoch, Minimal};

    use super::*;

    fn pow(tag: u8, parent: u8, difficulty: u64) -> PowBlock {
        PowBlock {
            block_hash: Hash32([tag; 32]),
            parent_hash: Hash32([parent; 32]),
            total_difficulty: U256::from(difficulty),
        }
    }

    #[test]
    fn only_the_first_block_past_the_threshold_is_terminal() {
        // Fixture state: a terminal difficulty of 100, and the chain 0x01(90) -> 0x02(100) -> 0x03(110).
        let config = ChainConfig {
            terminal_total_difficulty: U256::from(100),
            ..ChainConfig::minimal()
        };
        let mut chain = PowChain::default();
        for block in [pow(1, 0, 90), pow(2, 1, 100), pow(3, 2, 110)] {
            chain.insert(block);
        }
        let check =
            |hash: u8| chain.validate_merge_block::<Minimal>(&config, Slot(1), Hash32([hash; 32]));

        // 0x02 crosses 100 while its parent sits at 90: terminal.
        assert_eq!(check(2), Ok(()));
        // 0x03's parent already crossed: too late.
        assert_eq!(
            check(3),
            Err(ForkChoiceError::NotTerminalPowBlock(Hash32([3; 32])))
        );
        // 0x01 has not crossed, and its parent 0x00 is unknown anyway.
        assert_eq!(
            check(1),
            Err(ForkChoiceError::UnknownPowBlock(Hash32([0; 32])))
        );
    }

    #[test]
    fn an_unvalidated_merge_block_imports_only_once_old_enough() {
        // Fixture state: a terminal difficulty of 100, and only 0x03(110) known, child of 0x02.
        let config = ChainConfig {
            terminal_total_difficulty: U256::from(100),
            ..ChainConfig::minimal()
        };
        let mut chain = PowChain::default();
        chain.insert(pow(3, 2, 110));
        let check = |slot: u64, current: u64, hash: u8| {
            chain.validate_optimistic_merge_block::<Minimal>(
                &config,
                Slot(slot),
                Slot(current),
                Hash32([hash; 32]),
            )
        };

        // At slot 127 a merge block of slot 0 is one slot short of the 128 required.
        assert_eq!(
            check(0, 127, 9),
            Err(ForkChoiceError::OptimisticMergeTooRecent {
                slot: Slot(0),
                current_slot: Slot(127),
                safe_slots: 128,
            })
        );
        // At slot 128 it may import, though the engine knows neither 0x09 nor its parent.
        assert_eq!(check(0, 128, 9), Ok(()));
        // A known 0x03 whose parent 0x02 is unknown is not excused.
        assert_eq!(
            check(0, 128, 3),
            Err(ForkChoiceError::UnknownPowBlock(Hash32([2; 32])))
        );
    }

    #[test]
    fn a_hand_fixed_terminal_hash_binds_unvalidated_merge_blocks_too() {
        // Fixture state: terminal block 0x07 fixed by hand from epoch 0, and no known blocks.
        let config = ChainConfig {
            terminal_block_hash: Hash32([7; 32]),
            terminal_block_hash_activation_epoch: Epoch(0),
            ..ChainConfig::minimal()
        };
        let chain = PowChain::default();

        // At slot 200 a merge block of slot 8 is old enough, yet must build on 0x07.
        assert_eq!(
            chain.validate_optimistic_merge_block::<Minimal>(
                &config,
                Slot(8),
                Slot(200),
                Hash32([9; 32])
            ),
            Err(ForkChoiceError::NotTerminalBlockHash {
                parent_hash: Hash32([9; 32]),
                terminal: Hash32([7; 32]),
            })
        );
        assert_eq!(
            chain.validate_optimistic_merge_block::<Minimal>(
                &config,
                Slot(8),
                Slot(200),
                Hash32([7; 32])
            ),
            Ok(())
        );
    }
}
