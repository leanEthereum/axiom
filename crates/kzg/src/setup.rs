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

use crate::{
    FIELD_ELEMENTS_PER_BLOB, KzgError, basis::Basis, bit_reversal::BitReversal, parallel::Threads,
};

/// The mainnet setup file, as c-kzg-4844 distributes it.
///
/// SHA-256: d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7.
const MAINNET: &str = include_str!("trusted_setup.txt");

/// Number of G2 powers in the setup, KZG_SETUP_G2_LENGTH in the Deneb spec.
///
/// Cell proofs open 64 points at once and need [s^64]_2, so 65 powers suffice.
const G2_POINTS: usize = 65;

/// Name of the G1 powers in setup files and errors.
const G1_MONOMIAL: &str = "G1 monomial";

/// Name of the G1 Lagrange basis in setup files and errors.
const G1_LAGRANGE: &str = "G1 Lagrange";

/// Name of the G2 powers in setup files and errors.
const G2_MONOMIAL: &str = "G2 monomial";

/// The decoded points of the trusted setup.
#[derive(Clone, Debug)]
pub(crate) struct TrustedSetup {
    /// The Lagrange basis in bit-reversal order, matching the order of blob evaluations.
    pub(crate) g1_lagrange_brp: Basis,
    /// The powers [s^i] in G1, in increasing order.
    pub(crate) g1_monomial: Basis,
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

    /// Decodes a setup given as compressed points, checking counts, curves, and subgroups.
    ///
    /// The Lagrange basis comes in natural order, as the setup files list it.
    ///
    /// # Errors
    ///
    /// Fails when a basis has another number of points than the scheme needs, or a point is invalid.
    pub(crate) fn from_compressed(
        g1_monomial: &[[u8; G1_COMPRESSED_BYTES]],
        g1_lagrange: &[[u8; G1_COMPRESSED_BYTES]],
        g2_monomial: &[[u8; G2_COMPRESSED_BYTES]],
    ) -> Result<Self, KzgError> {
        for (basis, expected, actual) in [
            (G1_MONOMIAL, FIELD_ELEMENTS_PER_BLOB, g1_monomial.len()),
            (G1_LAGRANGE, FIELD_ELEMENTS_PER_BLOB, g1_lagrange.len()),
            (G2_MONOMIAL, G2_POINTS, g2_monomial.len()),
        ] {
            if actual != expected {
                return Err(KzgError::SetupLength {
                    basis,
                    expected,
                    actual,
                });
            }
        }
        // An operator's file is not a constant of the crate, so every point gets its subgroup check.
        let threads = Threads::available();
        let g1 = |basis: &'static str, points: &[[u8; G1_COMPRESSED_BYTES]]| {
            let indexed: Vec<(usize, &[u8; G1_COMPRESSED_BYTES])> =
                points.iter().enumerate().collect();
            threads.map::<_, _, Result<Vec<G1Affine>, KzgError>>(&indexed, |(index, bytes)| {
                G1Affine::from_compressed(bytes).map_err(|source| KzgError::InvalidSetupPoint {
                    basis,
                    index: *index,
                    source,
                })
            })
        };
        let g1_monomial = g1(G1_MONOMIAL, g1_monomial)?;
        let mut g1_lagrange_brp = g1(G1_LAGRANGE, g1_lagrange)?;
        let g2_monomial = g2_monomial
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                G2Affine::from_compressed(bytes).map_err(|source| KzgError::InvalidSetupPoint {
                    basis: G2_MONOMIAL,
                    index,
                    source,
                })
            })
            .collect::<Result<Vec<G2Affine>, KzgError>>()?;
        BitReversal::of_length(FIELD_ELEMENTS_PER_BLOB).permute(&mut g1_lagrange_brp);
        Ok(Self {
            g1_lagrange_brp: Basis::new(g1_lagrange_brp),
            g1_monomial: Basis::new(g1_monomial),
            g2_monomial,
        })
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
        let lagrange_lines: Vec<HexLine<'_>> = lines.by_ref().take(g1_count).map(HexLine).collect();
        let g2_lines: Vec<HexLine<'_>> = lines.by_ref().take(g2_count).map(HexLine).collect();
        let monomial_lines: Vec<HexLine<'_>> = lines.by_ref().take(g1_count).map(HexLine).collect();
        if lines.any(|line| !line.is_empty()) {
            return None;
        }

        // Phase 3: decompress every point.
        // Each G1 decompression is one square root, so the 8192 of them run on all cores.
        let threads = Threads::available();
        let g1_lagrange_brp: Option<Vec<G1Affine>> =
            threads.map(&lagrange_lines, |line| line.to_g1());
        let g1_monomial: Option<Vec<G1Affine>> = threads.map(&monomial_lines, |line| line.to_g1());
        let g2_monomial: Option<Vec<G2Affine>> = threads.map(&g2_lines, |line| line.to_g2());
        let (mut g1_lagrange_brp, g1_monomial, g2_monomial) =
            (g1_lagrange_brp?, g1_monomial?, g2_monomial?);
        if [g1_lagrange_brp.len(), g1_monomial.len()] != [g1_count; 2]
            || g2_monomial.len() != g2_count
        {
            return None;
        }

        // Phase 4: the spec indexes the Lagrange basis in bit-reversal order, like the blob.
        BitReversal::of_length(FIELD_ELEMENTS_PER_BLOB).permute(&mut g1_lagrange_brp);
        Some(Self {
            g1_lagrange_brp: Basis::new(g1_lagrange_brp),
            g1_monomial: Basis::new(g1_monomial),
            g2_monomial,
        })
    }
}

/// One point line of the setup file: a compressed point in hex digits, with no prefix.
#[derive(Clone, Copy, Debug)]
struct HexLine<'a>(&'a str);

impl HexLine<'_> {
    /// Decodes a G1 point on the curve, without the subgroup check.
    fn to_g1(self) -> Option<G1Affine> {
        G1Affine::from_compressed_unchecked(&self.to_bytes::<G1_COMPRESSED_BYTES>()?).ok()
    }

    /// Decodes a G2 point on the curve, without the subgroup check.
    fn to_g2(self) -> Option<G2Affine> {
        G2Affine::from_compressed_unchecked(&self.to_bytes::<G2_COMPRESSED_BYTES>()?).ok()
    }

    /// Decodes exactly N bytes from 2N hex digits.
    fn to_bytes<const N: usize>(self) -> Option<[u8; N]> {
        let (pairs, odd) = self.0.as_bytes().as_chunks::<2>();
        if pairs.len() != N || !odd.is_empty() {
            return None;
        }
        let mut bytes = [0; N];
        // A digit is one of 0-9, a-f, or A-F, worth at most 15, so the narrowing is exact.
        let digit = |ascii: u8| char::from(ascii).to_digit(16).map(|value| value as u8);
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = (digit(*high)? << 4) | digit(*low)?;
        }
        Some(bytes)
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
        let g1_points: Vec<&G1Affine> = setup
            .g1_lagrange_brp
            .points()
            .iter()
            .chain(setup.g1_monomial.points())
            .collect();
        let in_subgroup: Vec<bool> =
            Threads::available().map(&g1_points, |point| point.is_torsion_free());
        assert!(in_subgroup.into_iter().all(|in_subgroup| in_subgroup));
        assert!(setup.g2_monomial.iter().all(G2Affine::is_torsion_free));
    }

    #[test]
    fn mainnet_bases_share_one_secret() {
        let setup = TrustedSetup::mainnet();

        // Both bases start from the generators: [s^0] = G1 and [s^0]_2 = G2.
        assert_eq!(setup.g1_monomial.points()[0], G1Affine::GENERATOR);
        assert_eq!(setup.g2_monomial[0], G2Affine::GENERATOR);

        // The G1 and G2 powers hide the same s: e([s], [1]_2) = e([1], [s]_2).
        assert_eq!(
            Gt::pairing(&setup.g1_monomial.points()[1], &setup.g2_monomial[0]),
            Gt::pairing(&setup.g1_monomial.points()[0], &setup.g2_monomial[1])
        );

        // The Lagrange basis sums to the constant polynomial one: sum_i L_i(s) = 1.
        let sum: G1Projective = setup
            .g1_lagrange_brp
            .points()
            .iter()
            .map(G1Projective::from)
            .sum();
        assert_eq!(G1Affine::from(sum), G1Affine::GENERATOR);
    }

    #[test]
    fn a_setup_of_compressed_points_decodes_as_the_embedded_one() {
        // The embedded points, compressed again and in natural order, rebuild the same setup.
        let mainnet = TrustedSetup::mainnet();
        let mut lagrange: Vec<G1Affine> = mainnet.g1_lagrange_brp.points().to_vec();
        BitReversal::of_length(FIELD_ELEMENTS_PER_BLOB).permute(&mut lagrange);
        let compress = |points: &[G1Affine]| -> Vec<[u8; G1_COMPRESSED_BYTES]> {
            points.iter().map(G1Affine::to_compressed).collect()
        };
        let g1_monomial = compress(mainnet.g1_monomial.points());
        let g1_lagrange = compress(&lagrange);
        let g2_monomial: Vec<[u8; G2_COMPRESSED_BYTES]> = mainnet
            .g2_monomial
            .iter()
            .map(G2Affine::to_compressed)
            .collect();
        let rebuilt =
            TrustedSetup::from_compressed(&g1_monomial, &g1_lagrange, &g2_monomial).unwrap();
        assert_eq!(
            rebuilt.g1_lagrange_brp.points(),
            mainnet.g1_lagrange_brp.points()
        );
        assert_eq!(rebuilt.g1_monomial.points(), mainnet.g1_monomial.points());
        assert_eq!(rebuilt.g2_monomial, mainnet.g2_monomial);

        // One G2 power short of the 65 the cell proofs need.
        assert_eq!(
            TrustedSetup::from_compressed(&g1_monomial, &g1_lagrange, &g2_monomial[..64])
                .unwrap_err(),
            KzgError::SetupLength {
                basis: G2_MONOMIAL,
                expected: 65,
                actual: 64,
            }
        );

        // A Lagrange point flipped to another encoding no longer decodes.
        let mut broken = g1_lagrange;
        broken[7] = [0xff; G1_COMPRESSED_BYTES];
        let source = G1Affine::from_compressed(&broken[7]).unwrap_err();
        assert_eq!(
            TrustedSetup::from_compressed(&g1_monomial, &broken, &g2_monomial).unwrap_err(),
            KzgError::InvalidSetupPoint {
                basis: G1_LAGRANGE,
                index: 7,
                source,
            }
        );
    }

    #[test]
    fn malformed_setups_are_rejected() {
        // A wrong header count no longer matches the blob size.
        assert!(TrustedSetup::parse("4095\n65\n").is_none());
        // A truncated file runs out of points.
        assert!(TrustedSetup::parse("4096\n65\nc0").is_none());
        // Hex digits must come in full pairs of valid digits.
        assert_eq!(HexLine("0g").to_bytes::<1>(), None);
        assert_eq!(HexLine("aB").to_bytes::<1>(), Some([0xab]));
    }
}
