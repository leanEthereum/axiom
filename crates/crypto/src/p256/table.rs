//! Precomputed multiples of the generator for fast fixed-base multiplication.

use std::sync::OnceLock;

use super::{
    field::FieldElement,
    point::{AffinePoint, ProjectivePoint},
    scalar::Scalar,
};
use crate::ct::Mask;

/// Number of 4-bit windows in a 256-bit scalar.
const WINDOWS: usize = 64;

/// Non-zero digits per window.
const ENTRIES: usize = 15;

/// The comb table, built on first use.
static TABLE: OnceLock<GeneratorTable> = OnceLock::new();

/// Every multiple j 16^i G for windows i = 0..63 and digits j = 1..15, in affine form.
///
/// # Overview
///
/// Writing k = sum_i d_i 16^i turns k G into a plain sum of table entries.
///
/// ```text
/// k G = sum_i  d_i 16^i G  =  sum_i  table[i][d_i]
/// ```
///
/// No doublings remain: 64 mixed additions make one fixed-base multiplication.
/// The table holds 64 * 15 points of 64 bytes, about 60 KiB.
pub(super) struct GeneratorTable {
    /// Row i, one of 64, holds j 16^i G at index j - 1.
    rows: Vec<[AffinePoint; ENTRIES]>,
}

impl GeneratorTable {
    /// The shared table, computed once per process.
    pub(super) fn get() -> &'static Self {
        TABLE.get_or_init(Self::build)
    }

    /// Computes every entry, then converts all of them to affine with one inversion.
    fn build() -> Self {
        // Phase 1: projective multiples, row by row.
        // The base of row i is 16^i G.
        let mut projective = Vec::with_capacity(WINDOWS * ENTRIES);
        let mut base = AffinePoint::GENERATOR.to_projective();
        for _ in 0..WINDOWS {
            let mut multiple = base;
            for _ in 0..ENTRIES {
                projective.push(multiple);
                multiple = multiple.add(&base);
            }
            base = base.double().double().double().double();
        }

        // Phase 2: batch inversion of every Z, per Montgomery's trick.
        //
        //     prefix[i] = z_0 z_1 ... z_i
        //     inv       = 1 / prefix[last]           the one inversion
        //     1 / z_i   = inv * prefix[i - 1], then inv = inv * z_i
        //
        // Invariant: j 16^i G is finite since j 16^i < n, so no Z is zero.
        let mut prefix = Vec::with_capacity(projective.len());
        let mut running = FieldElement::ONE;
        for point in &projective {
            running = running.mul(point.z);
            prefix.push(running);
        }
        let mut inverse = running.invert();
        let mut affine = vec![AffinePoint::GENERATOR; projective.len()];
        for i in (0..projective.len()).rev() {
            let z_inv = if i == 0 {
                inverse
            } else {
                inverse.mul(prefix[i - 1])
            };
            inverse = inverse.mul(projective[i].z);
            affine[i] = AffinePoint {
                x: projective[i].x.mul(z_inv),
                y: projective[i].y.mul(z_inv),
            };
        }

        // Phase 3: lay the points out as rows of 15.
        let (rows, _) = affine.as_chunks::<ENTRIES>();
        Self {
            rows: rows.to_vec(),
        }
    }

    /// k G for a secret scalar, in constant time.
    ///
    /// The complete mixed addition has no exceptional inputs.
    /// The only masked case is a zero digit, whose entry the affine table cannot hold.
    pub(super) fn mul_ct(&self, k: &Scalar) -> ProjectivePoint {
        let mut acc = ProjectivePoint::IDENTITY;
        for (window, row) in self.rows.iter().enumerate() {
            let digit = k.nibble(window);

            // Scan the whole row so the digit picks no address.
            let mut entry = row[0];
            for (j, candidate) in (1..).zip(row) {
                entry = AffinePoint::select(Mask::equal(digit, j), *candidate, entry);
            }

            // A zero digit adds nothing: keep acc.
            let sum = acc.add_affine(&entry);
            acc = ProjectivePoint::select(Mask::is_zero(digit), &acc, &sum);
        }
        acc
    }

    /// a G + b Q for public scalars and a public point.
    ///
    /// Verification runs this on public data only.
    /// Zero digits skip their addition, so the time depends on the scalars.
    pub(super) fn double_mul_vartime(
        &self,
        a: &Scalar,
        b: &Scalar,
        q: &AffinePoint,
    ) -> ProjectivePoint {
        // The generator part: one addition per non-zero digit, no doublings.
        let mut acc = ProjectivePoint::IDENTITY;
        for (window, row) in self.rows.iter().enumerate() {
            let digit = a.nibble(window) as usize;
            if digit != 0 {
                acc = acc.add_affine(&row[digit - 1]);
            }
        }

        // The arbitrary point: width-5 NAF.
        acc.add(&q.to_projective().mul_vartime(b))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::p256::{point::tests::mul_reference, scalar::tests::arb_scalar};

    #[test]
    fn rows_hold_the_right_multiples() {
        // Row 0 starts at G, row 1 at 16 G, and entry 14 of row 0 is 15 G.
        let table = GeneratorTable::get();
        let g = Some(AffinePoint::GENERATOR);
        let small = |value: u8| {
            let mut bytes = [0_u8; 32];
            bytes[31] = value;
            Scalar::from_bytes(&bytes).unwrap()
        };
        assert_eq!(table.rows[0][0], AffinePoint::GENERATOR);
        assert_eq!(Some(table.rows[1][0]), mul_reference(g, &small(16)));
        assert_eq!(Some(table.rows[0][14]), mul_reference(g, &small(15)));
    }

    #[test]
    fn edge_scalars() {
        // 0 gives the identity, and n - 1 gives -G.
        let table = GeneratorTable::get();
        assert!(table.mul_ct(&Scalar::ZERO).is_identity().reveal());
        assert_eq!(
            table.mul_ct(&Scalar::ONE.neg()).to_affine(),
            Some(AffinePoint::GENERATOR.neg())
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn constant_time_comb_matches_variable_time_and_reference(k in arb_scalar()) {
            // The constant-time comb equals the variable-time NAF and the textbook method.
            let g = AffinePoint::GENERATOR;
            let comb = GeneratorTable::get().mul_ct(&k);
            prop_assert!(comb.equals(&g.to_projective().mul_vartime(&k)).reveal());
            prop_assert_eq!(comb.to_affine(), mul_reference(Some(g), &k));
        }

        #[test]
        fn double_multiplication_matches_two_products(
            a in arb_scalar(),
            b in arb_scalar(),
            c in arb_scalar(),
        ) {
            // a G + b Q with Q = c G equals (a + b c) G.
            let table = GeneratorTable::get();
            let expected = table.mul_ct(&a.add(b.mul(c)));
            match table.mul_ct(&c).to_affine() {
                Some(q) => {
                    let fast = table.double_mul_vartime(&a, &b, &q);
                    prop_assert!(fast.equals(&expected).reveal());
                }
                None => prop_assert_eq!(c, Scalar::ZERO),
            }
        }
    }
}
