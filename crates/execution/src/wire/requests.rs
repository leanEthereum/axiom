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
//! See `get_execution_requests_list` in the Electra beacon chain spec,
//! and its inverse `get_execution_requests` in the Electra validator spec.

use axiom_json::{Data, Json};
use axiom_ssz::Ssz;
use axiom_types::{
    ExecutionRequests, Preset,
    constants::{CONSOLIDATION_REQUEST_TYPE, DEPOSIT_REQUEST_TYPE, WITHDRAWAL_REQUEST_TYPE},
};

use super::{JsonCodec, Reader};
use crate::{RequestsError, WireError, WireErrorKind};

/// The execution requests list: typed byte strings, one per non-empty request type.
///
/// Encoding always yields a valid list.
/// A list read from the engine is checked only when decoded into requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestsList(Vec<Vec<u8>>);

impl RequestsList {
    /// Flattens the requests into the typed byte strings the engine expects.
    #[must_use]
    pub fn encode<P: Preset>(requests: &ExecutionRequests<P>) -> Self {
        // The three lists, already in ascending type order.
        let typed = [
            (
                DEPOSIT_REQUEST_TYPE,
                requests.deposits.is_empty(),
                requests.deposits.encode(),
            ),
            (
                WITHDRAWAL_REQUEST_TYPE,
                requests.withdrawals.is_empty(),
                requests.withdrawals.encode(),
            ),
            (
                CONSOLIDATION_REQUEST_TYPE,
                requests.consolidations.is_empty(),
                requests.consolidations.encode(),
            ),
        ];
        // Empty lists are dropped; the rest gain their type byte in front.
        Self(
            typed
                .into_iter()
                .filter(|(_, empty, _)| !empty)
                .map(|(kind, _, data)| {
                    let mut element = Vec::with_capacity(1 + data.len());
                    element.push(kind);
                    element.extend_from_slice(&data);
                    element
                })
                .collect(),
        )
    }

    /// Rebuilds the requests, enforcing every rule of the list.
    ///
    /// # Errors
    ///
    /// Fails on an unknown type, an element without data, types out of order or repeated,
    /// and data that is not the SSZ list its type requires.
    pub fn decode<P: Preset>(&self) -> Result<ExecutionRequests<P>, RequestsError> {
        let mut requests = ExecutionRequests::<P>::default();
        let mut previous: Option<u8> = None;

        for element in &self.0 {
            // Split the type byte from the data; a lone type byte has no data.
            let Some((&kind, data)) = element.split_first() else {
                return Err(RequestsError::MissingType);
            };
            if ![
                DEPOSIT_REQUEST_TYPE,
                WITHDRAWAL_REQUEST_TYPE,
                CONSOLIDATION_REQUEST_TYPE,
            ]
            .contains(&kind)
            {
                return Err(RequestsError::UnknownType(kind));
            }
            if data.is_empty() {
                return Err(RequestsError::Empty(kind));
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
            let ssz = |error| RequestsError::Ssz(kind, error);
            match kind {
                DEPOSIT_REQUEST_TYPE => requests.deposits = Ssz::decode(data).map_err(ssz)?,
                WITHDRAWAL_REQUEST_TYPE => requests.withdrawals = Ssz::decode(data).map_err(ssz)?,
                _ => requests.consolidations = Ssz::decode(data).map_err(ssz)?,
            }
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

impl<P: Preset> JsonCodec for ExecutionRequests<P> {
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
mod tests {
    use axiom_ssz::List;
    use axiom_types::{ConsolidationRequest, DepositRequest, ExecutionAddress, Minimal};

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
        assert_eq!(list.decode::<Minimal>(), Ok(sample()));
    }

    #[test]
    fn list_rule_violations() {
        let list = RequestsList::encode(&sample());
        let (deposits, consolidations) = (list.as_slice()[0].clone(), list.as_slice()[1].clone());

        // Reversed order, a repeat, a lone type byte, and an unknown type.
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
            (vec![vec![0x01]], RequestsError::Empty(0x01)),
            (vec![Vec::new()], RequestsError::MissingType),
            (vec![vec![0x03, 0xff]], RequestsError::UnknownType(0x03)),
        ];
        for (list, expected) in cases {
            assert_eq!(RequestsList::from(list).decode::<Minimal>(), Err(expected));
        }

        // A deposit list one byte short of a whole request fails its SSZ decoding.
        let mut truncated = deposits;
        truncated.pop();
        assert!(matches!(
            RequestsList::from(vec![truncated]).decode::<Minimal>(),
            Err(RequestsError::Ssz(0x00, _))
        ));
    }
}
