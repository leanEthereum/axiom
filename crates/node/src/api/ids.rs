//! Block and state identifiers, as beacon API paths name them.

use std::str::FromStr;

use axiom_http::Request;
use axiom_json::{Data, Json};
use axiom_state_transition::State;
use axiom_types::{
    BlsPubkey, ChainConfig, Preset, Root, Slot, ValidatorIndex, accessors::CoreState,
};

use super::{ApiContext, ApiError, reply::Freshness};
use crate::{Chain, ChainError, StoredBlock};

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

    /// The block this names, as stored, and its root, or a 404.
    ///
    /// # Errors
    ///
    /// Fails with a 404 when the node knows no such block.
    pub(crate) fn find<P: Preset>(
        self,
        chain: &Chain<P>,
    ) -> Result<(Root, StoredBlock<P>), ApiError> {
        let root = self
            .resolve(chain)?
            .ok_or_else(|| ApiError::not_found("block not found"))?;
        let block = chain
            .stored_block(root)?
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
            Self::Root(root) => Ok(chain.stored_block(root)?.map(|_| root)),
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

impl StateId {
    /// Finds the state this names, by value, with the block it follows and its freshness.
    ///
    /// # Overview
    ///
    /// A keyword or slot names the canonical state at a slot.
    /// When no block was proposed at that slot, the block before it is advanced through the empty slots.
    /// The justified and finalized keywords name the checkpoint state, at the start of its epoch.
    ///
    /// Advancing runs slot and epoch processing, so it is left to the caller, off the chain thread.
    ///
    /// # Errors
    ///
    /// Fails with a 404 when the node knows no such state or no longer holds it.
    pub(crate) fn locate<P: Preset>(self, chain: &Chain<P>) -> Result<StateView<P>, ApiError> {
        let head = chain.head();
        let (root, target) = match self {
            Self::Root(state_root) => {
                let root = self
                    .resolve(chain)?
                    .ok_or_else(|| ApiError::not_found(format!("state {state_root} not found")))?;
                (root, None)
            }
            Self::Block(BlockId::Root(root)) => (root, None),
            Self::Block(BlockId::Head) => (head.root, None),
            Self::Block(BlockId::Finalized) => (
                head.finalized.root,
                Some(head.finalized.epoch.start_slot::<P>()),
            ),
            Self::Block(BlockId::Justified) => (
                head.justified.root,
                Some(head.justified.epoch.start_slot::<P>()),
            ),
            Self::Block(BlockId::Genesis) => (Self::canonical(chain, Slot(0))?, Some(Slot(0))),
            Self::Block(BlockId::Slot(slot)) => {
                // A slot the clock has not reached has no state yet.
                if slot > chain.store().current_slot() {
                    return Err(ApiError::not_found(format!("slot {slot} is in the future")));
                }
                (Self::canonical(chain, slot)?, Some(slot))
            }
        };
        let state = chain
            .state_by_block(root)?
            .ok_or_else(|| ApiError::not_found(format!("state of block {root} is not held")))?;
        // Only a later slot needs advancing; an earlier one is the block's own slot.
        let target = target.filter(|target| *target > state.beacon().slot());
        let slot = target.unwrap_or_else(|| state.beacon().slot());
        Ok(StateView {
            state,
            freshness: ApiContext::freshness(chain, root, slot),
            target,
        })
    }

    /// The canonical block at or before a slot, or a 404.
    fn canonical<P: Preset>(chain: &Chain<P>, slot: Slot) -> Result<Root, ApiError> {
        chain.canonical_root_at_or_before(slot)?.ok_or_else(|| {
            ApiError::not_found(format!("no canonical block at or before slot {slot}"))
        })
    }
}

/// A state a request named, held by value.
///
/// States share their large collections, so holding one by value is cheap.
#[derive(Clone, Debug)]
pub(crate) struct StateView<P: Preset> {
    /// The state.
    pub state: State<P>,
    /// Whether the state is optimistic and whether it is finalized.
    pub freshness: Freshness,
    /// The slot the state still has to reach through empty slots, if any.
    target: Option<Slot>,
}

impl<P: Preset> StateView<P> {
    /// Runs the empty slots up to the slot the request named.
    ///
    /// # Errors
    ///
    /// Fails with a 500 when slot processing fails, which a valid state never does.
    pub(crate) fn advance(&mut self, config: &ChainConfig) -> Result<(), ApiError> {
        if let Some(target) = self.target.take() {
            self.state
                .process_slots(config, target)
                .map_err(|error| ApiError::internal(format!("cannot advance state: {error}")))?;
        }
        Ok(())
    }
}

/// A validator named in a request: its index or its public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValidatorId {
    /// An index into the registry.
    Index(ValidatorIndex),
    /// A 48-byte public key.
    Pubkey(BlsPubkey),
}

impl FromStr for ValidatorId {
    type Err = ApiError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || ApiError::bad_request(format!("invalid validator id: {text}"));
        if text.starts_with("0x") {
            <[u8; 48]>::from_data(text)
                .map(|bytes| Self::Pubkey(BlsPubkey(bytes)))
                .map_err(|_| invalid())
        } else {
            text.parse()
                .map(|index| Self::Index(ValidatorIndex(index)))
                .map_err(|_| invalid())
        }
    }
}

impl ValidatorId {
    /// The validators a request body lists, as a JSON array of identifier strings.
    ///
    /// An empty body lists none, which routes read as every validator.
    ///
    /// # Errors
    ///
    /// Fails with a bad request when the body is not such an array.
    pub(crate) fn list_from_body(body: &[u8]) -> Result<Vec<Self>, ApiError> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        let json = Json::parse(body)
            .map_err(|error| ApiError::bad_request(format!("malformed body: {error}")))?;
        let items = json
            .as_array()
            .ok_or_else(|| ApiError::bad_request("body is not an array of validator ids"))?;
        items
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or_else(|| ApiError::bad_request("a validator id is not a string"))?
                    .parse()
            })
            .collect()
    }

    /// The registry index this names in a state, if the validator exists there.
    pub(crate) fn index<P: Preset>(self, state: &mut State<P>) -> Option<ValidatorIndex> {
        match self {
            Self::Index(index) => {
                let known = (index.0 as usize) < state.beacon().validators().len();
                known.then_some(index)
            }
            Self::Pubkey(pubkey) => state.validator_index(&pubkey),
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
    fn validator_ids_are_indices_or_keys() {
        let key = format!("0x{}", "cd".repeat(48));
        assert_eq!("7".parse(), Ok(ValidatorId::Index(ValidatorIndex(7))));
        assert_eq!(key.parse(), Ok(ValidatorId::Pubkey(BlsPubkey([0xcd; 48]))));

        // A short key and a negative index are both refused.
        for text in ["0xcd", "-1"] {
            assert_eq!(
                text.parse::<ValidatorId>(),
                Err(ApiError::bad_request(format!(
                    "invalid validator id: {text}"
                ))),
                "{text}"
            );
        }
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
