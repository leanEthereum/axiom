//! Block, state, and validator identifiers, as beacon API paths and queries name them.

use std::str::FromStr;

use axiom_http::Request;
use axiom_json::Data;
use axiom_types::{BlsPubkey, Preset, Root, Slot, ValidatorIndex, combined::SignedBeaconBlock};

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
    /// The block identifier in a request's path.
    ///
    /// # Errors
    ///
    /// Fails with a bad request when the path names no block, or names one badly.
    pub(crate) fn from_request(request: &Request) -> Result<Self, ApiError> {
        request
            .param("block_id")
            .ok_or_else(|| ApiError::bad_request("missing block id"))?
            .parse()
    }

    /// The block this names and its root, or a 404.
    ///
    /// # Errors
    ///
    /// Fails with a 404 when the node knows no such block.
    pub(crate) fn find<P: Preset>(
        self,
        chain: &Chain<P>,
    ) -> Result<(Root, SignedBeaconBlock<P>), ApiError> {
        let root = self
            .resolve(chain)?
            .ok_or_else(|| ApiError::not_found("block not found"))?;
        let block = chain
            .block(root)?
            .ok_or_else(|| ApiError::not_found("block not found"))?;
        Ok((root, block))
    }

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
    /// The state identifier in a request's path.
    ///
    /// # Errors
    ///
    /// Fails with a bad request when the path names no state, or names one badly.
    pub(crate) fn from_request(request: &Request) -> Result<Self, ApiError> {
        request
            .param("state_id")
            .ok_or_else(|| ApiError::bad_request("missing state id"))?
            .parse()
    }

    /// The block whose post-state this names, and its root, or a 404.
    ///
    /// # Errors
    ///
    /// Fails with a 404 when the node holds no such state.
    pub(crate) fn find_block<P: Preset>(
        self,
        chain: &Chain<P>,
    ) -> Result<(Root, SignedBeaconBlock<P>), ApiError> {
        let root = self
            .resolve(chain)?
            .ok_or_else(|| ApiError::not_found("state not found"))?;
        let block = chain
            .block(root)?
            .ok_or_else(|| ApiError::not_found("state not found"))?;
        Ok((root, block))
    }

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
                        .is_some_and(|block| block.message().state_root() == state_root)
                    {
                        return Ok(Some(*root));
                    }
                }
                Ok(None)
            }
        }
    }
}

/// A validator named by its registry index or by its key.
///
/// ```text
///     12345 | 0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValidatorId {
    /// A position in the registry.
    Index(ValidatorIndex),
    /// A key, which names at most one validator: deposits of a known key top it up.
    Pubkey(BlsPubkey),
}

impl FromStr for ValidatorId {
    type Err = ApiError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || ApiError::bad_request(format!("invalid validator id: {text}"));
        if text.starts_with("0x") {
            return <[u8; 48]>::from_data(text)
                .map(|bytes| Self::Pubkey(BlsPubkey(bytes)))
                .map_err(|_| invalid());
        }
        text.parse()
            .map(|index| Self::Index(ValidatorIndex(index)))
            .map_err(|_| invalid())
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

        // A validator is a decimal index or a 48-byte key.
        let key = format!("0x{}", "cd".repeat(48));
        assert_eq!("7".parse(), Ok(ValidatorId::Index(ValidatorIndex(7))));
        assert_eq!(key.parse(), Ok(ValidatorId::Pubkey(BlsPubkey([0xcd; 48]))));
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
        // A 32-byte root is no key, and a keyword is no index.
        let root = format!("0x{}", "ab".repeat(32));
        for text in [root.as_str(), "head"] {
            assert_eq!(
                text.parse::<ValidatorId>(),
                Err(ApiError::bad_request(format!(
                    "invalid validator id: {text}"
                ))),
                "{text}"
            );
        }
    }
}
