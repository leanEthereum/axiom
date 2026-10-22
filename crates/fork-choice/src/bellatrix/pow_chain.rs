//! The proof-of-work blocks a node knows, and the terminal block check of the merge.

use std::collections::HashMap;

use axiom_types::{ChainConfig, Hash32, Preset, Slot, bellatrix::PowBlock};

use crate::ForkChoiceError;

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
}

#[cfg(test)]
mod tests {
    use axiom_ssz::U256;
    use axiom_types::Minimal;

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
}
