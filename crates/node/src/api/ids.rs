//! Block and state identifiers, as beacon API paths name them.

use std::str::FromStr;

use axiom_json::Data;
use axiom_types::{Preset, Root, Slot};

use super::ApiError;
use crate::{Chain, ChainError};

/// A block named in a path: a keyword, a slot, or a root.
///
/// ```text
///     head | genesis | finalized | justified | 12345 | 0x4b36...
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockId {
    /// The canonical head.
    Head,
    /// The block at slot zero.
    Genesis,
    /// The latest finalized checkpoint's block.
    Finalized,
    /// The latest justified checkpoint's block.
    Justified,
    /// The canonical block at a slot.
    Slot(Slot),
    /// A block by its root, canonical or not.
    Root(Root),
}

impl FromStr for BlockId {
    type Err = ApiError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "head" => Ok(Self::Head),
            "genesis" => Ok(Self::Genesis),
            "finalized" => Ok(Self::Finalized),
            "justified" => Ok(Self::Justified),
            // Anything with a hex prefix must be a whole 32-byte root.
            _ if text.starts_with("0x") => <[u8; 32]>::from_data(text)
                .map(|bytes| Self::Root(Root(bytes)))
                .map_err(|_| ApiError::bad_request(format!("invalid block id: {text}"))),
            _ => text
                .parse()
                .map(|slot| Self::Slot(Slot(slot)))
                .map_err(|_| ApiError::bad_request(format!("invalid block id: {text}"))),
        }
    }
}

impl BlockId {
    /// The root of the block this names, if the node knows one.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn resolve<P: Preset>(self, chain: &Chain<P>) -> Result<Option<Root>, ChainError> {
        let head = chain.head();
        match self {
            Self::Head => Ok(Some(head.root)),
            Self::Finalized => Ok(Some(head.finalized.root)),
            Self::Justified => Ok(Some(head.justified.root)),
            Self::Genesis => chain.canonical_root(Slot(0)),
            Self::Slot(slot) => chain.canonical_root(slot),
            // A root is known when its block is stored, whichever branch it is on.
            Self::Root(root) => Ok(chain.block(root)?.map(|_| root)),
        }
    }
}

/// A state named in a path: a block identifier, or the state's own root.
///
/// States are kept by the root of the block they follow.
/// A state root is found by looking through the blocks since finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StateId {
    /// The post-state of a block.
    Block(BlockId),
    /// A state by its own root.
    Root(Root),
}

impl FromStr for StateId {
    type Err = ApiError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // A hex root names a state directly; everything else names it through its block.
        match text.parse::<BlockId>()? {
            BlockId::Root(root) => Ok(Self::Root(root)),
            block => Ok(Self::Block(block)),
        }
    }
}

impl StateId {
    /// The root of the block whose post-state this names, if the node holds that state.
    ///
    /// # Errors
    ///
    /// Fails when the database is unreadable.
    pub(crate) fn resolve<P: Preset>(self, chain: &Chain<P>) -> Result<Option<Root>, ChainError> {
        match self {
            Self::Block(block) => block.resolve(chain),
            Self::Root(state_root) => {
                // Only blocks since finality have states in memory, so only they can match.
                for (root, _) in chain.store().blocks().iter() {
                    if chain
                        .block(*root)?
                        .is_some_and(|block| block.message.state_root == state_root)
                    {
                        return Ok(Some(*root));
                    }
                }
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_parse_from_every_form() {
        let root = format!("0x{}", "ab".repeat(32));
        assert_eq!("head".parse(), Ok(BlockId::Head));
        assert_eq!("genesis".parse(), Ok(BlockId::Genesis));
        assert_eq!("finalized".parse(), Ok(BlockId::Finalized));
        assert_eq!("justified".parse(), Ok(BlockId::Justified));
        assert_eq!("42".parse(), Ok(BlockId::Slot(Slot(42))));
        assert_eq!(root.parse(), Ok(BlockId::Root(Root([0xab; 32]))));

        // A root names a state directly, a keyword names it through its block.
        assert_eq!(root.parse(), Ok(StateId::Root(Root([0xab; 32]))));
        assert_eq!("head".parse(), Ok(StateId::Block(BlockId::Head)));
    }

    #[test]
    fn malformed_identifiers_are_bad_requests() {
        // A short root, a negative slot, and an unknown keyword.
        for text in ["0xabcd", "-1", "latest"] {
            assert_eq!(
                text.parse::<BlockId>(),
                Err(ApiError::bad_request(format!("invalid block id: {text}"))),
                "{text}"
            );
        }
    }
}
