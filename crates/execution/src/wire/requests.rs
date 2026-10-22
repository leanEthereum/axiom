//! The execution requests list of EIP-7685, as the engine API carries it.
//!
//! Each element is one type byte followed by the SSZ list of that type's requests.
//! Types appear in strictly ascending order, and an empty list is left out entirely.
//!
//! ```text
//!     container                    list sent to the engine
//!     deposits:       [d1, d2]     0x00 || ssz([d1, d2])
//!     withdrawals:    []           (omitted)
//!     consolidations: [c1]         0x02 || ssz([c1])
//! ```
//!
//! Electra defines three request types, and Gloas adds builder deposits and builder exits.
//! See `get_execution_requests_list` in the Electra and Gloas beacon chain specs.
//! Its inverse is `get_execution_requests`, in the Electra validator spec.

use axiom_json::{Data, Json};
use axiom_ssz::{DecodeError, Ssz};
use axiom_types::{
    Preset,
    constants::{
        BUILDER_DEPOSIT_REQUEST_TYPE, BUILDER_EXIT_REQUEST_TYPE, CONSOLIDATION_REQUEST_TYPE,
        DEPOSIT_REQUEST_TYPE, WITHDRAWAL_REQUEST_TYPE,
    },
    electra, gloas,
};

use super::{JsonCodec, Reader};
use crate::{RequestsError, WireError, WireErrorKind};

/// One fork's execution requests, as SSZ lists keyed by their type byte.
///
/// Electra and Gloas know different sets of request types.
pub trait TypedRequests: Default {
    /// The type bytes this fork defines, in ascending order.
    const TYPES: &'static [u8];

    /// Each type with the SSZ encoding of its list, in ascending type order.
    fn encode_lists(&self) -> Vec<(u8, Vec<u8>)>;

    /// Replaces the list of one of the fork's types with the decoding of its bytes.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the SSZ list that type requires.
    fn decode_list(&mut self, kind: u8, data: &[u8]) -> Result<(), DecodeError>;
}

impl<P: Preset> TypedRequests for electra::ExecutionRequests<P> {
    const TYPES: &'static [u8] = &[
        DEPOSIT_REQUEST_TYPE,
        WITHDRAWAL_REQUEST_TYPE,
        CONSOLIDATION_REQUEST_TYPE,
    ];

    fn encode_lists(&self) -> Vec<(u8, Vec<u8>)> {
        vec![
            (DEPOSIT_REQUEST_TYPE, self.deposits.encode()),
            (WITHDRAWAL_REQUEST_TYPE, self.withdrawals.encode()),
            (CONSOLIDATION_REQUEST_TYPE, self.consolidations.encode()),
        ]
    }

    fn decode_list(&mut self, kind: u8, data: &[u8]) -> Result<(), DecodeError> {
        // Invariant: the kind is one of the three types, checked by the caller.
        match kind {
            DEPOSIT_REQUEST_TYPE => self.deposits = Ssz::decode(data)?,
            WITHDRAWAL_REQUEST_TYPE => self.withdrawals = Ssz::decode(data)?,
            _ => self.consolidations = Ssz::decode(data)?,
        }
        Ok(())
    }
}

impl TypedRequests for gloas::ExecutionRequests {
    const TYPES: &'static [u8] = &[
        DEPOSIT_REQUEST_TYPE,
        WITHDRAWAL_REQUEST_TYPE,
        CONSOLIDATION_REQUEST_TYPE,
        BUILDER_DEPOSIT_REQUEST_TYPE,
        BUILDER_EXIT_REQUEST_TYPE,
    ];

    fn encode_lists(&self) -> Vec<(u8, Vec<u8>)> {
        vec![
            (DEPOSIT_REQUEST_TYPE, self.deposits.encode()),
            (WITHDRAWAL_REQUEST_TYPE, self.withdrawals.encode()),
            (CONSOLIDATION_REQUEST_TYPE, self.consolidations.encode()),
            (BUILDER_DEPOSIT_REQUEST_TYPE, self.builder_deposits.encode()),
            (BUILDER_EXIT_REQUEST_TYPE, self.builder_exits.encode()),
        ]
    }

    fn decode_list(&mut self, kind: u8, data: &[u8]) -> Result<(), DecodeError> {
        // Invariant: the kind is one of the five types, checked by the caller.
        match kind {
            DEPOSIT_REQUEST_TYPE => self.deposits = Ssz::decode(data)?,
            WITHDRAWAL_REQUEST_TYPE => self.withdrawals = Ssz::decode(data)?,
            CONSOLIDATION_REQUEST_TYPE => self.consolidations = Ssz::decode(data)?,
            BUILDER_DEPOSIT_REQUEST_TYPE => self.builder_deposits = Ssz::decode(data)?,
            _ => self.builder_exits = Ssz::decode(data)?,
        }
        Ok(())
    }
}

/// The execution requests list: typed byte strings, one per non-empty request type.
///
/// Encoding always yields a valid list.
/// A list read from the engine is checked only when decoded into requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestsList(Vec<Vec<u8>>);

impl RequestsList {
    /// Flattens the requests into the typed byte strings the engine expects.
    #[must_use]
    pub fn encode<R: TypedRequests>(requests: &R) -> Self {
        // Every request type is fixed-size, so a list encodes to no bytes exactly when empty.
        // Empty lists are dropped; the rest gain their type byte in front.
        Self(
            requests
                .encode_lists()
                .into_iter()
                .filter(|(_, data)| !data.is_empty())
                .map(|(kind, data)| {
                    let mut element = Vec::with_capacity(1 + data.len());
                    element.push(kind);
                    element.extend_from_slice(&data);
                    element
                })
                .collect(),
        )
    }

    /// Rebuilds one fork's requests, enforcing every rule of the list.
    ///
    /// # Errors
    ///
    /// Fails on the first broken rule:
    ///
    /// - a type the fork lacks, or an element without a type or without data;
    /// - types out of order or repeated;
    /// - data that is not the SSZ list its type requires.
    pub fn decode<R: TypedRequests>(&self) -> Result<R, RequestsError> {
        let mut requests = R::default();
        let mut previous: Option<u8> = None;

        for (index, element) in self.0.iter().enumerate() {
            // Split the type byte from the data; a lone type byte has no data.
            let Some((&kind, data)) = element.split_first() else {
                return Err(RequestsError::MissingType { index });
            };
            if !R::TYPES.contains(&kind) {
                return Err(RequestsError::UnknownType { index, kind });
            }
            if data.is_empty() {
                return Err(RequestsError::Empty { index, kind });
            }

            // Strictly ascending, which also rules out a type appearing twice.
            //
            //     0x00, 0x02        ok
            //     0x02, 0x00        out of order
            //     0x01, 0x01        repeated
            if let Some(previous) = previous
                && kind <= previous
            {
                return Err(RequestsError::OutOfOrder {
                    previous,
                    current: kind,
                });
            }
            previous = Some(kind);

            // Decode the data as the SSZ list of that type, limits included.
            requests
                .decode_list(kind, data)
                .map_err(|error| RequestsError::Ssz(kind, error))?;
        }
        Ok(requests)
    }

    /// The typed byte strings, in list order.
    #[must_use]
    pub fn as_slice(&self) -> &[Vec<u8>] {
        &self.0
    }
}

impl From<Vec<Vec<u8>>> for RequestsList {
    /// Wraps typed byte strings as received, without checking them.
    fn from(elements: Vec<Vec<u8>>) -> Self {
        Self(elements)
    }
}

impl JsonCodec for RequestsList {
    /// An array of DATA, one element per typed byte string.
    fn to_json(&self) -> Json {
        Json::Array(
            self.0
                .iter()
                .map(|element| Json::String(element.to_data()))
                .collect(),
        )
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        // Decode each DATA element, locating a bad one by its index.
        Reader::new(value).items()?.decode().map(Self)
    }
}

impl<P: Preset> JsonCodec for electra::ExecutionRequests<P> {
    /// The requests list in its JSON form.
    fn to_json(&self) -> Json {
        RequestsList::encode(self).to_json()
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        RequestsList::from_json(value)?
            .decode()
            .map_err(|error| WireError::new(WireErrorKind::Requests(error)))
    }
}

impl JsonCodec for gloas::ExecutionRequests {
    /// The requests list in its JSON form.
    fn to_json(&self) -> Json {
        RequestsList::encode(self).to_json()
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        RequestsList::from_json(value)?
            .decode()
            .map_err(|error| WireError::new(WireErrorKind::Requests(error)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use axiom_ssz::{List, ProgressiveList};
    use axiom_types::{
        BlsPubkey, BlsSignature, Bytes32, ExecutionAddress, Gwei, Minimal,
        electra::{ConsolidationRequest, DepositRequest, ExecutionRequests, WithdrawalRequest},
        gloas::{BuilderDepositRequest, BuilderExitRequest},
    };
    use proptest::prelude::*;

    use super::*;

    /// Requests with two deposits, no withdrawals, and one consolidation.
    fn sample() -> ExecutionRequests<Minimal> {
        let deposit = |index| DepositRequest {
            index,
            ..DepositRequest::default()
        };
        let consolidation = ConsolidationRequest {
            source_address: ExecutionAddress([0x11; 20]),
            ..ConsolidationRequest::default()
        };
        ExecutionRequests {
            deposits: List::try_from(vec![deposit(1), deposit(2)]).unwrap(),
            withdrawals: List::default(),
            consolidations: List::try_from(vec![consolidation]).unwrap(),
        }
    }

    #[test]
    fn empty_lists_are_omitted() {
        // Two elements: type 0x00 then type 0x02; withdrawals are empty and absent.
        let list = RequestsList::encode(&sample());
        let elements = list.as_slice();
        assert_eq!(elements.len(), 2);
        assert_eq!((elements[0][0], elements[1][0]), (0x00, 0x02));
        assert_eq!(&elements[0][1..], sample().deposits.encode().as_slice());

        // No requests at all is the empty list, never a list of empty elements.
        assert_eq!(
            RequestsList::encode(&ExecutionRequests::<Minimal>::default()),
            RequestsList::default()
        );
    }

    #[test]
    fn decode_inverts_encode() {
        let list = RequestsList::encode(&sample());
        assert_eq!(list.decode::<ExecutionRequests<Minimal>>(), Ok(sample()));
    }

    #[test]
    fn list_rule_violations() {
        let list = RequestsList::encode(&sample());
        let (deposits, consolidations) = (list.as_slice()[0].clone(), list.as_slice()[1].clone());

        // Reversed order, a repeat, a lone type byte, an empty element, and an unknown type.
        // The last three sit at position 1, after a valid deposit element.
        let cases = [
            (
                vec![consolidations, deposits.clone()],
                RequestsError::OutOfOrder {
                    previous: 0x02,
                    current: 0x00,
                },
            ),
            (
                vec![deposits.clone(), deposits.clone()],
                RequestsError::OutOfOrder {
                    previous: 0x00,
                    current: 0x00,
                },
            ),
            (
                vec![deposits.clone(), vec![0x01]],
                RequestsError::Empty {
                    index: 1,
                    kind: 0x01,
                },
            ),
            (
                vec![deposits.clone(), Vec::new()],
                RequestsError::MissingType { index: 1 },
            ),
            (
                vec![deposits.clone(), vec![0x05, 0xff]],
                RequestsError::UnknownType {
                    index: 1,
                    kind: 0x05,
                },
            ),
        ];
        for (list, expected) in cases {
            assert_eq!(
                RequestsList::from(list).decode::<ExecutionRequests<Minimal>>(),
                Err(expected)
            );
        }

        // A deposit list one byte short of a whole request fails its SSZ decoding.
        let mut truncated = deposits;
        truncated.pop();
        assert!(matches!(
            RequestsList::from(vec![truncated]).decode::<ExecutionRequests<Minimal>>(),
            Err(RequestsError::Ssz(0x00, _))
        ));
    }

    #[test]
    fn builder_requests_exist_only_from_gloas() {
        // One builder exit request: 20 address bytes and 48 key bytes, typed 0x04.
        let gloas = gloas::ExecutionRequests {
            builder_exits: ProgressiveList::from(vec![BuilderExitRequest::default()]),
            ..gloas::ExecutionRequests::default()
        };
        let list = RequestsList::encode(&gloas);
        assert_eq!(list.as_slice(), [[vec![0x04], vec![0; 68]].concat()]);

        // Gloas reads it back; Electra knows no type 0x04.
        assert_eq!(list.decode::<gloas::ExecutionRequests>(), Ok(gloas));
        assert_eq!(
            list.decode::<ExecutionRequests<Minimal>>(),
            Err(RequestsError::UnknownType {
                index: 0,
                kind: 0x04
            })
        );
    }

    /// Any Electra requests with up to three of each type.
    pub(crate) fn electra_requests() -> impl Strategy<Value = ExecutionRequests<Minimal>> {
        let deposit =
            (any::<u8>(), any::<u64>(), any::<u64>()).prop_map(|(byte, amount, index)| {
                DepositRequest {
                    pubkey: BlsPubkey([byte; 48]),
                    withdrawal_credentials: Bytes32([byte; 32]),
                    amount: Gwei(amount),
                    signature: BlsSignature([byte; 96]),
                    index,
                }
            });
        let withdrawal = (any::<u8>(), any::<u64>()).prop_map(|(byte, amount)| WithdrawalRequest {
            source_address: ExecutionAddress([byte; 20]),
            validator_pubkey: BlsPubkey([byte; 48]),
            amount: Gwei(amount),
        });
        let consolidation = any::<u8>().prop_map(|byte| ConsolidationRequest {
            source_address: ExecutionAddress([byte; 20]),
            source_pubkey: BlsPubkey([byte; 48]),
            target_pubkey: BlsPubkey([byte.wrapping_add(1); 48]),
        });
        (
            proptest::collection::vec(deposit, 0..3),
            proptest::collection::vec(withdrawal, 0..3),
            proptest::collection::vec(consolidation, 0..=2),
        )
            .prop_map(
                |(deposits, withdrawals, consolidations)| ExecutionRequests {
                    deposits: List::try_from(deposits).expect("within the limit"),
                    withdrawals: List::try_from(withdrawals).expect("within the limit"),
                    consolidations: List::try_from(consolidations).expect("within the limit"),
                },
            )
    }

    /// Any Gloas requests: Electra's three types plus up to two of each builder type.
    pub(crate) fn gloas_requests() -> impl Strategy<Value = gloas::ExecutionRequests> {
        let builder_deposit =
            (any::<u8>(), any::<u64>()).prop_map(|(byte, amount)| BuilderDepositRequest {
                pubkey: BlsPubkey([byte; 48]),
                withdrawal_credentials: Bytes32([byte; 32]),
                amount: Gwei(amount),
                signature: BlsSignature([byte; 96]),
            });
        let builder_exit = any::<u8>().prop_map(|byte| BuilderExitRequest {
            source_address: ExecutionAddress([byte; 20]),
            pubkey: BlsPubkey([byte; 48]),
        });
        (
            electra_requests(),
            proptest::collection::vec(builder_deposit, 0..=2),
            proptest::collection::vec(builder_exit, 0..=2),
        )
            .prop_map(|(electra, builder_deposits, builder_exits)| {
                gloas::ExecutionRequests {
                    deposits: electra.deposits.iter().cloned().collect(),
                    withdrawals: electra.withdrawals.iter().cloned().collect(),
                    consolidations: electra.consolidations.iter().cloned().collect(),
                    builder_deposits: ProgressiveList::from(builder_deposits),
                    builder_exits: ProgressiveList::from(builder_exits),
                }
            })
    }

    proptest! {
        #[test]
        fn electra_requests_list_round_trip(requests in electra_requests()) {
            // The list holds one element per non-empty type, in ascending type order.
            let list = RequestsList::encode(&requests);
            let elements = list.as_slice();
            let non_empty = [
                !requests.deposits.is_empty(),
                !requests.withdrawals.is_empty(),
                !requests.consolidations.is_empty(),
            ];
            prop_assert_eq!(elements.len(), non_empty.iter().filter(|&&present| present).count());
            prop_assert!(elements.windows(2).all(|pair| pair[0][0] < pair[1][0]));
            prop_assert_eq!(list.decode::<ExecutionRequests<Minimal>>(), Ok(requests.clone()));

            // The JSON array form decodes back too.
            prop_assert_eq!(ExecutionRequests::<Minimal>::from_json(&requests.to_json()), Ok(requests));
        }

        #[test]
        fn gloas_requests_list_round_trip(requests in gloas_requests()) {
            // Five types now; still one element per non-empty type, ascending.
            let list = RequestsList::encode(&requests);
            let elements = list.as_slice();
            let non_empty = [
                !requests.deposits.is_empty(),
                !requests.withdrawals.is_empty(),
                !requests.consolidations.is_empty(),
                !requests.builder_deposits.is_empty(),
                !requests.builder_exits.is_empty(),
            ];
            prop_assert_eq!(elements.len(), non_empty.iter().filter(|&&present| present).count());
            prop_assert!(elements.windows(2).all(|pair| pair[0][0] < pair[1][0]));
            prop_assert_eq!(gloas::ExecutionRequests::from_json(&requests.to_json()), Ok(requests));
        }

        #[test]
        fn requests_decoder_never_panics(
            list in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..400), 0..4),
        ) {
            // Arbitrary elements either decode or fail; nothing in between.
            let list = RequestsList::from(list);
            let _ = list.decode::<ExecutionRequests<Minimal>>();
            let _ = list.decode::<gloas::ExecutionRequests>();
        }
    }
}
