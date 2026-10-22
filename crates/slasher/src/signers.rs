//! The signers of a stored vote and their aggregate signature, in compact form.

use axiom_types::{BlsSignature, ValidatorIndex};

use crate::SlasherError;

/// Who signed a vote, and the aggregate signature that proves it.
///
/// # Overview
///
/// The indices are sorted, so each is stored as its gap from the one before, in LEB128.
/// A committee of 500 drawn from a million validators has gaps near 2000, two bytes each.
/// An aggregate over a whole slot has gaps near 32, one byte each.
/// That is a quarter or an eighth of the eight bytes the spec's encoding spends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Signers {
    /// Aggregate signature of every signer.
    pub(crate) signature: BlsSignature,
    /// The signers, sorted and unique.
    pub(crate) indices: Vec<ValidatorIndex>,
}

impl Signers {
    /// Table name, for errors.
    const TABLE: &'static str = "signers";

    /// The signature, then the gaps between sorted indices.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.indices.len() * 2);
        out.extend_from_slice(&self.signature.0);
        let mut previous = 0;
        for index in &self.indices {
            // Invariant: sorted indices never step back, so the gap is never negative.
            let mut gap = index.0 - previous;
            previous = index.0;
            loop {
                let low = (gap & 0x7f) as u8;
                gap >>= 7;
                if gap == 0 {
                    out.push(low);
                    break;
                }
                out.push(low | 0x80);
            }
        }
        out
    }

    /// The signers from their stored form.
    ///
    /// # Errors
    ///
    /// Fails when the signature is cut short, a gap is unterminated, or an index overflows.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, SlasherError> {
        let corrupt = |reason| SlasherError::Corrupt {
            table: Self::TABLE,
            len: bytes.len(),
            reason,
        };
        let (signature, mut rest) = bytes
            .split_first_chunk::<96>()
            .ok_or_else(|| corrupt("no signature"))?;
        let mut indices = Vec::new();
        let mut previous: u64 = 0;
        while !rest.is_empty() {
            let mut gap: u64 = 0;
            let mut shift = 0;
            loop {
                let (&byte, tail) = rest
                    .split_first()
                    .ok_or_else(|| corrupt("unterminated gap"))?;
                rest = tail;
                // Threshold: the tenth group starts at bit 63 and may hold one bit only.
                if shift >= 64 || (shift == 63 && byte & 0x7e != 0) {
                    return Err(corrupt("gap longer than 64 bits"));
                }
                gap |= u64::from(byte & 0x7f) << shift;
                shift += 7;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            previous = previous
                .checked_add(gap)
                .ok_or_else(|| corrupt("index overflows"))?;
            indices.push(ValidatorIndex(previous));
        }
        Ok(Self {
            signature: BlsSignature(*signature),
            indices,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection::btree_set, prelude::*};

    use super::*;

    #[test]
    fn small_gaps_take_one_byte() {
        // Indices 5, 6, 200: gaps 5, 1, 194; the last needs two bytes.
        let signers = Signers {
            signature: BlsSignature([7; 96]),
            indices: vec![ValidatorIndex(5), ValidatorIndex(6), ValidatorIndex(200)],
        };
        let bytes = signers.encode();
        assert_eq!(&bytes[96..], &[5, 1, 0xc2, 0x01]);
        assert_eq!(Signers::decode(&bytes).expect("decodes"), signers);
    }

    #[test]
    fn malformed_records_are_refused() {
        // 95 bytes hold no signature.
        assert!(matches!(
            Signers::decode(&[0; 95]),
            Err(SlasherError::Corrupt {
                reason: "no signature",
                ..
            })
        ));
        // A continuation bit on the last byte leaves the gap open.
        let mut open = vec![0; 96];
        open.push(0x80);
        assert!(matches!(
            Signers::decode(&open),
            Err(SlasherError::Corrupt {
                reason: "unterminated gap",
                ..
            })
        ));
        // Eleven continuation groups exceed 64 bits.
        let mut long = vec![0; 96];
        long.extend([0xff; 10]);
        long.push(0x01);
        assert!(matches!(
            Signers::decode(&long),
            Err(SlasherError::Corrupt {
                reason: "gap longer than 64 bits",
                ..
            })
        ));
    }

    proptest! {
        #[test]
        fn any_sorted_index_set_round_trips(indices in btree_set(any::<u64>(), 0..64)) {
            let signers = Signers {
                signature: BlsSignature([1; 96]),
                indices: indices.into_iter().map(ValidatorIndex).collect(),
            };
            prop_assert_eq!(Signers::decode(&signers.encode()).expect("decodes"), signers);
        }
    }
}
