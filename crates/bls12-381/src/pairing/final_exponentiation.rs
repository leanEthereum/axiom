//! The final exponentiation, which maps a Miller loop output to its unique representative in GT.
//!
//! # Overview
//!
//! The Miller loop value is only defined up to r-th powers.
//! Raising it to (p^12 - 1) / r removes that ambiguity and lands in the order-r group GT.
//! The exponent factors into an easy part and a hard part:
//!
//! ```text
//!     (p^12 - 1) / r = (p^6 - 1) (p^2 + 1) * (p^4 - p^2 + 1) / r
//!                      \_______ easy ____/   \______ hard ______/
//! ```
//!
//! The easy part costs one inversion and Frobenius maps.
//! Its output lies in the cyclotomic subgroup, where squaring is cheap and inversion is conjugation.

use super::BLS_X;
use crate::Fp12;

/// Raises a Miller loop output to 3 (p^12 - 1) / r.
///
/// The extra factor 3 is coprime to r, so the map stays a bijection onto GT.
/// Every pairing in this crate carries it, so equalities between pairings are unaffected.
///
/// # Returns
///
/// The power, or zero when the input is zero.
/// Zero never equals one, so a degenerate input can never pass a pairing check.
pub(super) fn final_exponentiation(f: &Fp12) -> Fp12 {
    // Phase 1, easy part: g = f^{(p^6 - 1)(p^2 + 1)}.
    //
    //     f^{p^6 - 1} = conj(f) / f
    let Some(inverse) = f.invert() else {
        return Fp12::ZERO;
    };
    let easy = f.conjugate() * inverse;
    //     g = easy^{p^2 + 1} = frob^2(easy) * easy
    let g = easy.frobenius_map().frobenius_map() * easy;

    // Phase 2, hard part, after Hayashida, Hayasaka, and Teruya, eprint 2020/875:
    //
    //     3 (p^4 - p^2 + 1) / r = (x - 1)^2 (x + p) (x^2 + p^2 - 1) + 3
    //
    // g^{(x - 1)^2}
    let step = exp_by_x(&g) * g.conjugate();
    let step = exp_by_x(&step) * step.conjugate();
    // Then raise to x + p.
    let step = exp_by_x(&step) * step.frobenius_map();
    // Then raise to x^2 + p^2 - 1.
    let step = exp_by_x(&exp_by_x(&step)) * step.frobenius_map().frobenius_map() * step.conjugate();
    // Finally multiply in g^3.
    step * g.cyclotomic_square() * g
}

/// Raises a cyclotomic-subgroup element to the curve parameter x = -0xd201000000010000.
pub(super) fn exp_by_x(f: &Fp12) -> Fp12 {
    // Square-and-multiply over |x|, whose top bit 63 seeds the accumulator.
    let mut acc = *f;
    for bit in (0..63).rev() {
        acc = acc.cyclotomic_square();
        if (BLS_X >> bit) & 1 == 1 {
            acc *= f;
        }
    }
    // x is negative, and inversion in the cyclotomic subgroup is conjugation.
    acc.conjugate()
}
