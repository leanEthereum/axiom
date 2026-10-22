//! The Miller loop of the optimal ate pairing, over many pairs at once.
//!
//! # Overview
//!
//! For P in G1 and Q in G2 the loop evaluates the Miller function f_{x,Q} at P.
//! That rational function has a known divisor:
//!
//! ```text
//!     div(f_{x,Q}) = x (Q) - ([x] Q) - (x - 1) (O)
//! ```
//!
//! The loop walks the bits of |x| like a double-and-add on Q.
//! Each step doubles or adds a running point R and multiplies f by the line through the points involved.
//!
//! ```text
//!     f <- f^2 * l_{R,R}(P)      R <- 2R        (every bit)
//!     f <- f   * l_{R,Q}(P)      R <- R + Q     (set bits)
//! ```
//!
//! Many pairs share the squaring of f, which is the expensive part.
//! A product of pairings therefore costs one loop with one squaring chain, plus one line per pair and step.

use super::BLS_X;
use crate::{Fp2, Fp12, G1Affine, G2Affine};

/// The running point R of one pair, in Jacobian coordinates on the twist.
///
/// (X, Y, Z) stands for the affine point (X / Z^2, Y / Z^3).
#[derive(Clone, Copy, Debug)]
struct MillerPoint {
    /// The Jacobian X coordinate.
    x: Fp2,
    /// The Jacobian Y coordinate.
    y: Fp2,
    /// The Jacobian Z coordinate.
    z: Fp2,
}

/// A line through points of the twist, untwisted and scaled, before evaluation at P.
///
/// After untwisting, the line evaluated at P = (x_P, y_P) is the sparse element
///
/// ```text
///     constant + (x_coefficient * x_P) v + (y_coefficient * y_P) v w
/// ```
///
/// Factors in proper subfields are dropped: the final exponentiation sends them to one.
#[derive(Clone, Copy, Debug)]
struct Line {
    /// The coefficient of 1.
    constant: Fp2,
    /// The coefficient that multiplies x_P, landing on v.
    x_coefficient: Fp2,
    /// The coefficient that multiplies y_P, landing on v w.
    y_coefficient: Fp2,
}

impl Line {
    /// Multiplies the accumulator by this line evaluated at the G1 point.
    fn evaluate(&self, f: &Fp12, p: &G1Affine) -> Fp12 {
        let at_x = self.x_coefficient.mul_by_fp(&p.x);
        let at_y = self.y_coefficient.mul_by_fp(&p.y);
        f.mul_by_014(&self.constant, &at_x, &at_y)
    }
}

impl MillerPoint {
    /// Lifts an affine twist point to Jacobian coordinates with Z = 1.
    const fn from_affine(q: &G2Affine) -> Self {
        // Z = 1 makes the Jacobian and affine coordinates coincide.
        Self {
            x: q.x,
            y: q.y,
            z: Fp2::ONE,
        }
    }

    /// Doubles R in place and returns the tangent line at the old R.
    ///
    /// Adapted from Costello, Lange, and Naehrig, "Faster pairing computations on curves with high-degree twists", eprint 2009/615, as refined in Aranha et al., eprint 2010/354, algorithm 26.
    fn double_step(&mut self) -> Line {
        // Phase 1: Jacobian doubling 2R, with the textbook names in brackets.
        //
        //     [A] = X^2, [B] = Y^2, [C] = B^2, [D] = 2((X + B)^2 - A - C), [E] = 3A, [F] = E^2
        let x_squared = self.x.square();
        let y_squared = self.y.square();
        let y_fourth = y_squared.square();
        let d = ((y_squared + self.x).square() - x_squared - y_fourth).double();
        let three_x_squared = x_squared.double() + x_squared;
        let x_plus_e = self.x + three_x_squared;
        let e_squared = three_x_squared.square();
        let z_squared = self.z.square();

        // X' = F - 2D, Z' = (Y + Z)^2 - B - Z^2 = 2 Y Z, Y' = E (D - X') - 8C
        self.x = e_squared - d.double();
        self.z = (self.z + self.y).square() - y_squared - z_squared;
        self.y = (d - self.x) * three_x_squared - y_fourth.double().double().double();

        // Phase 2: the tangent line at the old R, scaled by 2 Y Z^3.
        //
        //     y coefficient : 2 Z' Z^2 = 4 Y Z^3
        //     x coefficient : -2 E Z^2 = -6 X^2 Z^2
        //     constant      : (X + E)^2 - A - F - 4B = 6 X^3 - 4 Y^2
        let y_coefficient = (self.z * z_squared).double();
        let x_coefficient = -(three_x_squared * z_squared).double();
        let constant = (x_plus_e.square() - x_squared - e_squared) - y_squared.double().double();
        Line {
            constant,
            x_coefficient,
            y_coefficient,
        }
    }

    /// Adds the affine Q into R in place and returns the line through the old R and Q.
    ///
    /// Mixed Jacobian-affine addition from eprint 2010/354, algorithm 27.
    fn add_step(&mut self, q: &G2Affine) -> Line {
        // Phase 1: bring Q to R's projective scale.
        //
        //     U2 = x_Q Z^2,  2 S2 = 2 y_Q Z^3
        let z_squared = self.z.square();
        let y_q_squared = q.y.square();
        let u2 = z_squared * q.x;
        let s2_doubled = ((q.y + self.z).square() - y_q_squared - z_squared) * z_squared;

        // Phase 2: chord slope numerator and denominator.
        //
        //     [H] = U2 - X,  [I] = 4 H^2,  [J] = H I,  slope = 2 (S2 - Y),  [V] = X I
        let h = u2 - self.x;
        let h_squared = h.square();
        let four_h_squared = h_squared.double().double();
        let j = four_h_squared * h;
        let slope = s2_doubled - self.y.double();
        let slope_x_q = slope * q.x;
        let v = four_h_squared * self.x;

        // Phase 3: Jacobian sum.
        //
        //     X' = slope^2 - J - 2V
        //     Z' = (Z + H)^2 - Z^2 - H^2 = 2 Z H
        //     Y' = slope (V - X') - 2 Y J
        self.x = slope.square() - j - v.double();
        self.z = (self.z + h).square() - z_squared - h_squared;
        self.y = (v - self.x) * slope - (self.y * j).double();

        // Phase 4: the chord through R and Q, evaluated through Q's coordinates.
        //
        //     y coefficient : 2 Z'
        //     x coefficient : -2 slope
        //     constant      : 2 slope x_Q - 2 y_Q Z'
        let y_q_z = (q.y + self.z).square() - y_q_squared - self.z.square();
        let constant = slope_x_q.double() - y_q_z;
        Line {
            constant,
            x_coefficient: -slope.double(),
            y_coefficient: self.z.double(),
        }
    }
}

/// Runs one Miller loop over every pair and returns the product of their values.
///
/// Pairs with a point at infinity contribute the factor one and are skipped.
pub(super) fn multi_miller_loop(terms: &[(G1Affine, G2Affine)]) -> Fp12 {
    // Each live pair carries its G1 point, its fixed Q, and its running R.
    let mut pairs: Vec<(G1Affine, G2Affine, MillerPoint)> = terms
        .iter()
        .filter(|(p, q)| !p.is_identity() && !q.is_identity())
        .map(|(p, q)| (*p, *q, MillerPoint::from_affine(q)))
        .collect();

    // The top bit 63 of |x| is the initial R = Q.
    // The loop covers bits 62 down to 0.
    let mut f = Fp12::ONE;
    for bit in (0..63).rev() {
        // f starts at one, so the first squaring is skipped.
        if bit != 62 {
            f = f.square();
        }
        for (p, _, r) in &mut pairs {
            f = r.double_step().evaluate(&f, p);
        }
        if (BLS_X >> bit) & 1 == 1 {
            for (p, q, r) in &mut pairs {
                f = r.add_step(q).evaluate(&f, p);
            }
        }
    }

    // x is negative: f_{-|x|,Q} = 1 / f_{|x|,Q} up to factors the final exponentiation kills.
    // After that exponentiation, conjugation equals inversion, and it is free.
    f.conjugate()
}
