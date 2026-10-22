//! Precomputed multiples of the generator for fast fixed-base multiplication.

use std::sync::OnceLock;

use super::{
    field::FieldElement,
    point::{AffinePoint, JacobianPoint},
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
    /// Row i holds j 16^i G at index j - 1; there are 64 rows.
    rows: Vec<[AffinePoint; ENTRIES]>,
}

impl GeneratorTable {
    /// The shared table, computed once per process.
    pub(super) fn get() -> &'static Self {
        TABLE.get_or_init(Self::build)
    }

    /// Computes every entry, then converts all of them to affine with one inversion.
    fn build() -> Self {
        // Phase 1: Jacobian multiples, row by row; the base of row i is 16^i G.
        let mut jacobian = Vec::with_capacity(WINDOWS * ENTRIES);
        let mut base = AffinePoint::GENERATOR.to_jacobian();
        for _ in 0..WINDOWS {
            let mut multiple = base;
            for _ in 0..ENTRIES {
                jacobian.push(multiple);
                multiple = multiple.add_vartime(&base);
            }
            base = base.double().double().double().double();
        }

        // Phase 2: batch inversion of every Z, per Montgomery's trick.
        //
        //     prefix[i] = z_0 z_1 ... z_i
        //     inv       = 1 / prefix[last]           the one inversion
        //     1 / z_i   = inv * prefix[i - 1], then inv = inv * z_i
        let mut prefix = Vec::with_capacity(jacobian.len());
        let mut running = FieldElement::ONE;
        for point in &jacobian {
            running = running.mul(point.z);
            prefix.push(running);
        }
        let mut inverse = running.invert();
        let mut affine = vec![AffinePoint::GENERATOR; jacobian.len()];
        for i in (0..jacobian.len()).rev() {
            let z_inv = if i == 0 {
                inverse
            } else {
                inverse.mul(prefix[i - 1])
            };
            inverse = inverse.mul(jacobian[i].z);
            let z_inv2 = z_inv.square();
            affine[i] = AffinePoint {
                x: jacobian[i].x.mul(z_inv2),
                y: jacobian[i].y.mul(z_inv2).mul(z_inv),
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
    /// # Exceptions
    ///
    /// Before window i, acc = L G with L = k mod 16^i < 16^i.
    /// The entry is d 16^i G with 1 <= d <= 15, and d 16^i < n even for i = 63.
    ///
    /// - L = d 16^i is impossible, since L < 16^i.
    /// - L + d 16^i = k mod 16^(i + 1) <= k < n, so L = -d 16^i mod n is impossible.
    ///
    /// The unchecked mixed addition is therefore exact, except for the two masked cases.
    pub(super) fn mul_ct(&self, k: &Scalar) -> JacobianPoint {
        let mut acc = JacobianPoint::IDENTITY;
        for (window, row) in self.rows.iter().enumerate() {
            let digit = k.nibble(window);

            // Scan the whole row so the digit picks no address.
            let mut entry = row[0];
            for (j, candidate) in (1..).zip(row) {
                entry = AffinePoint::select(Mask::equal(digit, j), *candidate, entry);
            }

            // Blend the exceptional cases away.
            //
            //     acc = 0, d != 0  -> the entry itself
            //     d = 0            -> acc unchanged
            let sum = acc.add_affine_unchecked(&entry);
            let sum = JacobianPoint::select(acc.is_identity(), &entry.to_jacobian(), &sum);
            acc = JacobianPoint::select(Mask::is_zero(digit), &acc, &sum);
        }
        acc
    }

    /// a G + b Q for public scalars and a public point.
    ///
    /// Verification and recovery run this on public data only.
    /// Zero digits skip their addition, so the time depends on the scalars.
    pub(super) fn double_mul_vartime(
        &self,
        a: &Scalar,
        b: &Scalar,
        q: &AffinePoint,
    ) -> JacobianPoint {
        // The generator part: one addition per non-zero digit, no doublings.
        let mut acc = JacobianPoint::IDENTITY;
        for (window, row) in self.rows.iter().enumerate() {
            let digit = a.nibble(window) as usize;
            if digit != 0 {
                acc = acc.add_affine_vartime(&row[digit - 1]);
            }
        }

        // The arbitrary point: width-5 NAF.
        acc.add_vartime(&q.to_jacobian().mul_vartime(b))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::secp256k1::{point::tests::mul_reference, scalar::tests::arb_scalar};

    #[test]
    fn rows_hold_the_right_multiples() {
        // Row 0 starts at G and row 1 at 16 G; entry 14 of row 0 is 15 G.
        let table = GeneratorTable::get();
        let g = AffinePoint::GENERATOR.to_jacobian();
        assert_eq!(table.rows[0][0], AffinePoint::GENERATOR);
        let sixteen = Scalar::from_bytes(&{
            let mut bytes = [0_u8; 32];
            bytes[31] = 16;
            bytes
        })
        .unwrap();
        assert_eq!(
            Some(table.rows[1][0]),
            mul_reference(&g, &sixteen).to_affine()
        );
        let fifteen = Scalar::from_bytes(&{
            let mut bytes = [0_u8; 32];
            bytes[31] = 15;
            bytes
        })
        .unwrap();
        assert_eq!(
            Some(table.rows[0][14]),
            mul_reference(&g, &fifteen).to_affine()
        );
    }

    #[test]
    fn edge_scalars() {
        // 0 gives the identity; n - 1 gives -G; both through the masked comb.
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
        fn comb_matches_double_and_add(k in arb_scalar()) {
            // The constant-time comb equals the textbook method on G.
            let reference = mul_reference(&AffinePoint::GENERATOR.to_jacobian(), &k);
            prop_assert!(GeneratorTable::get().mul_ct(&k).equals(&reference).reveal());
        }

        #[test]
        fn double_multiplication_matches_two_references(a in arb_scalar(), b in arb_scalar(), c in arb_scalar()) {
            // a G + b Q with Q = c G, against the sum of two textbook products.
            let g = AffinePoint::GENERATOR.to_jacobian();
            let q = mul_reference(&g, &c);
            let expected = mul_reference(&g, &a).add_vartime(&mul_reference(&q, &b));
            match q.to_affine() {
                Some(q) => {
                    let fast = GeneratorTable::get().double_mul_vartime(&a, &b, &q);
                    prop_assert!(fast.equals(&expected).reveal());
                }
                None => prop_assert!(c == Scalar::ZERO),
            }
        }
    }
}
