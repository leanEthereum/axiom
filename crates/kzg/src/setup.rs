//! The mainnet trusted setup of the KZG ceremony, embedded and decoded once.
//!
//! # Overview
//!
//! The setup holds powers of a secret s that nobody knows, hidden in the exponent:
//!
//! ```text
//!     G1 monomial   [s^0], [s^1], ..., [s^4095]                       commits coefficients
//!     G1 Lagrange   [L_0(s)], ..., [L_4095(s)]                        commits evaluations
//!     G2 monomial   [s^0]_2, ..., [s^64]_2                            checks openings
//! ```
//!
//! L_i is the Lagrange basis polynomial of the i-th root of unity of order 4096.
//!
//! The text format is the one c-kzg-4844 ships as trusted_setup.txt:
//!
//! ```text
//!     4096                        number of G1 points per basis
//!     65                          number of G2 points
//!     4096 lines                  G1 Lagrange, natural order, compressed hex
//!     65 lines                    G2 monomial, compressed hex
//!     4096 lines                  G1 monomial, compressed hex
//! ```

use axiom_bls12_381::{G1_COMPRESSED_BYTES, G1Affine, G2_COMPRESSED_BYTES, G2Affine};

use crate::{FIELD_ELEMENTS_PER_BLOB, fft::bit_reverse_permute, parallel};

/// The mainnet setup file, as c-kzg-4844 distributes it.
///
/// SHA-256: d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7.
const MAINNET: &str = include_str!("trusted_setup.txt");

/// Number of G2 powers in the setup, KZG_SETUP_G2_LENGTH in the Deneb spec.
///
/// Cell proofs open 64 points at once and need [s^64]_2, so 65 powers suffice.
const G2_POINTS: usize = 65;

/// The decoded points of the trusted setup.
#[derive(Clone, Debug)]
pub(crate) struct TrustedSetup {
    /// The Lagrange basis in bit-reversal order, matching the order of blob evaluations.
    pub(crate) g1_lagrange_brp: Vec<G1Affine>,
    /// The powers [s^i] in G1, in increasing order.
    pub(crate) g1_monomial: Vec<G1Affine>,
    /// The powers [s^i]_2 in G2, in increasing order.
    pub(crate) g2_monomial: Vec<G2Affine>,
}

impl TrustedSetup {
    /// Decodes the embedded mainnet setup.
    ///
    /// # Performance
    ///
    /// Decoding skips the subgroup checks, which would triple its cost.
    /// The file is a constant of the crate, and a test proves every point lies in its subgroup.
    pub(crate) fn mainnet() -> Self {
        // Invariant: the embedded file is fixed and a unit test decodes it, so this never fails.
        let Some(setup) = Self::parse(MAINNET) else {
            unreachable!("the embedded mainnet trusted setup decodes");
        };
        setup
    }

    /// Decodes a setup in the text format, checking counts and the curve equation.
    ///
    /// # Returns
    ///
    /// The setup, or nothing when a count, a hex string, or a point is malformed.
    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines().map(str::trim);

        // Phase 1: the header fixes the shape this crate is built for.
        let g1_count: usize = lines.next()?.parse().ok()?;
        let g2_count: usize = lines.next()?.parse().ok()?;
        if g1_count != FIELD_ELEMENTS_PER_BLOB || g2_count != G2_POINTS {
            return None;
        }

        // Phase 2: the three point lists, in file order.
        let lagrange_lines: Vec<&str> = lines.by_ref().take(g1_count).collect();
        let g2_lines: Vec<&str> = lines.by_ref().take(g2_count).collect();
        let monomial_lines: Vec<&str> = lines.by_ref().take(g1_count).collect();
        if lines.any(|line| !line.is_empty()) {
            return None;
        }

        // Phase 3: decompress every point.
        // Each G1 decompression is one square root, so the 8192 of them run on all cores.
        let mut g1_lagrange_brp = decode_all(&lagrange_lines, decode_g1)?;
        let g1_monomial = decode_all(&monomial_lines, decode_g1)?;
        let g2_monomial = decode_all(&g2_lines, decode_g2)?;
        if [g1_lagrange_brp.len(), g1_monomial.len()] != [g1_count; 2]
            || g2_monomial.len() != g2_count
        {
            return None;
        }

        // Phase 4: the spec indexes the Lagrange basis in bit-reversal order, like the blob.
        bit_reverse_permute(&mut g1_lagrange_brp);
        Some(Self {
            g1_lagrange_brp,
            g1_monomial,
            g2_monomial,
        })
    }
}

/// Decodes every line in parallel, failing when any line fails.
fn decode_all<P: Send>(lines: &[&str], decode: fn(&str) -> Option<P>) -> Option<Vec<P>> {
    parallel::map(lines, |line| decode(line))
        .into_iter()
        .collect()
}

/// Decodes one compressed G1 point on the curve, without the subgroup check.
fn decode_g1(line: &str) -> Option<G1Affine> {
    let bytes: [u8; G1_COMPRESSED_BYTES] = decode_hex(line)?;
    G1Affine::from_compressed_unchecked(&bytes).ok()
}

/// Decodes one compressed G2 point on the curve, without the subgroup check.
fn decode_g2(line: &str) -> Option<G2Affine> {
    let bytes: [u8; G2_COMPRESSED_BYTES] = decode_hex(line)?;
    G2Affine::from_compressed_unchecked(&bytes).ok()
}

/// Decodes exactly N bytes from 2N hex digits, with no prefix.
fn decode_hex<const N: usize>(line: &str) -> Option<[u8; N]> {
    let (pairs, odd) = line.as_bytes().as_chunks::<2>();
    if pairs.len() != N || !odd.is_empty() {
        return None;
    }
    let mut bytes = [0; N];
    for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
        *byte = (hex_value(*high)? << 4) | hex_value(*low)?;
    }
    Some(bytes)
}

/// The value of one hex digit, in either case.
const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use axiom_bls12_381::{G1Projective, Gt};

    use super::*;

    #[test]
    fn mainnet_points_lie_in_their_subgroups() {
        // Decoding skips the subgroup checks, so this test is what licenses that shortcut.
        let setup = TrustedSetup::mainnet();
        let g1_points = setup.g1_lagrange_brp.iter().chain(&setup.g1_monomial);
        assert!(
            parallel::map(&g1_points.collect::<Vec<_>>(), |point| point
                .is_torsion_free())
            .into_iter()
            .all(|in_subgroup| in_subgroup)
        );
        assert!(setup.g2_monomial.iter().all(G2Affine::is_torsion_free));
    }

    #[test]
    fn mainnet_bases_share_one_secret() {
        let setup = TrustedSetup::mainnet();

        // Both bases start from the generators: [s^0] = G1 and [s^0]_2 = G2.
        assert_eq!(setup.g1_monomial[0], G1Affine::GENERATOR);
        assert_eq!(setup.g2_monomial[0], G2Affine::GENERATOR);

        // The G1 and G2 powers hide the same s: e([s], [1]_2) = e([1], [s]_2).
        assert_eq!(
            Gt::pairing(&setup.g1_monomial[1], &setup.g2_monomial[0]),
            Gt::pairing(&setup.g1_monomial[0], &setup.g2_monomial[1])
        );

        // The Lagrange basis sums to the constant polynomial one: sum_i L_i(s) = 1.
        let sum: G1Projective = setup.g1_lagrange_brp.iter().map(G1Projective::from).sum();
        assert_eq!(G1Affine::from(sum), G1Affine::GENERATOR);
    }

    #[test]
    fn malformed_setups_are_rejected() {
        // A wrong header count no longer matches the blob size.
        assert!(TrustedSetup::parse("4095\n65\n").is_none());
        // A truncated file runs out of points.
        assert!(TrustedSetup::parse("4096\n65\nc0").is_none());
        // Hex digits must come in full pairs of valid digits.
        assert_eq!(decode_hex::<1>("0g"), None);
        assert_eq!(decode_hex::<1>("aB"), Some([0xab]));
    }
}
