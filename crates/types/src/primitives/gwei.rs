//! Amounts of ether.

use std::{
    fmt,
    iter::Sum,
    ops::{Add, AddAssign, Div, Mul, Sub, SubAssign},
};

use axiom_ssz::{DecodeError, Root, Ssz};

/// An amount of ether in gwei, one billionth of an ether.
///
/// Every balance, reward, and penalty is counted in gwei.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Gwei(pub u64);

impl Gwei {
    /// No ether.
    pub const ZERO: Self = Self(0);

    /// One ether.
    pub const ETHER: Self = Self(1_000_000_000);

    /// The sum, or nothing on overflow.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(sum) => Some(Self(sum)),
            None => None,
        }
    }

    /// The difference, or nothing when it would be negative.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(difference) => Some(Self(difference)),
            None => None,
        }
    }

    /// The difference, floored at zero.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// The sum, capped at the largest amount.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }
}

impl From<u64> for Gwei {
    fn from(amount: u64) -> Self {
        Self(amount)
    }
}

impl fmt::Display for Gwei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} gwei", self.0)
    }
}

impl Add for Gwei {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl AddAssign for Gwei {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl Sub for Gwei {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl SubAssign for Gwei {
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0;
    }
}

impl Mul<u64> for Gwei {
    type Output = Self;

    fn mul(self, factor: u64) -> Self {
        Self(self.0 * factor)
    }
}

impl Div<u64> for Gwei {
    type Output = Self;

    fn div(self, divisor: u64) -> Self {
        Self(self.0 / divisor)
    }
}

impl Div for Gwei {
    type Output = u64;

    /// How many times one amount fits in another.
    fn div(self, divisor: Self) -> u64 {
        self.0 / divisor.0
    }
}

impl Sum for Gwei {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl Ssz for Gwei {
    const FIXED_SIZE: Option<usize> = u64::FIXED_SIZE;
    const PACKED_SIZE: Option<usize> = u64::PACKED_SIZE;

    fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    fn encode_to(&self, out: &mut Vec<u8>) {
        self.0.encode_to(out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        u64::decode(bytes).map(Self)
    }

    fn hash_tree_root(&self) -> Root {
        self.0.hash_tree_root()
    }
}
