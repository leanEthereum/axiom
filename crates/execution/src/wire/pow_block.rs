//! The reply to eth_getBlockByHash, read as the proof-of-work block the merge checks.
//!
//! Defined by the execution JSON-RPC spec, `src/eth/block.yaml` in execution-apis.
//!
//! ```text
//!     {"hash":"0x..","parentHash":"0x..","totalDifficulty":"0x..",...}   known block
//!     null                                                            unknown block
//! ```
//!
//! The current schema no longer lists the total difficulty.
//! Engines of the merge era return it, and the terminal block check cannot run without it.
//! Every other member of the block is ignored.

use axiom_json::Json;
use axiom_types::bellatrix::PowBlock;

use super::{Fields, JsonCodec};
use crate::WireError;

impl JsonCodec for PowBlock {
    fn to_json(&self) -> Json {
        Json::from([
            ("hash", self.block_hash.to_json()),
            ("parentHash", self.parent_hash.to_json()),
            ("totalDifficulty", self.total_difficulty.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            block_hash: fields.required("hash")?,
            parent_hash: fields.required("parentHash")?,
            total_difficulty: fields.required("totalDifficulty")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::U256;
    use axiom_types::Hash32;

    use super::*;
    use crate::WireErrorKind;

    /// A block object with the given members after the hash, as an engine writes it.
    fn block_text(parent_digits: usize, rest: &str) -> Json {
        let text = format!(
            r#"{{"number":"0x9","hash":"0x{}","parentHash":"0x{}"{rest}}}"#,
            "11".repeat(32),
            "22".repeat(parent_digits),
        );
        Json::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn a_block_reads_its_three_members_and_ignores_the_rest() {
        // Hash 0x11.., parent 0x22.., total difficulty 0x3e8, plus number and difficulty.
        let json = block_text(32, r#","totalDifficulty":"0x3e8","difficulty":"0x1""#);

        // The number and difficulty members are dropped; 0x3e8 is 1000.
        let expected = PowBlock {
            block_hash: Hash32([0x11; 32]),
            parent_hash: Hash32([0x22; 32]),
            total_difficulty: U256::from(1000),
        };
        assert_eq!(PowBlock::from_json(&json), Ok(expected.clone()));
        assert_eq!(PowBlock::from_json(&expected.to_json()), Ok(expected));
    }

    #[test]
    fn a_block_without_its_total_difficulty_is_malformed() {
        // A block in the current schema: hash and parent, but no total difficulty.
        let json = block_text(32, "");

        assert_eq!(
            PowBlock::from_json(&json),
            Err(WireError::new(WireErrorKind::Missing).in_member("totalDifficulty"))
        );
    }

    #[test]
    fn a_short_parent_hash_is_located() {
        // The parent hash holds 31 bytes instead of 32.
        let json = block_text(31, r#","totalDifficulty":"0x1""#);

        assert_eq!(
            PowBlock::from_json(&json),
            Err(WireError::new(WireErrorKind::WrongLength {
                expected: 32,
                actual: 31
            })
            .in_member("parentHash"))
        );
    }
}
