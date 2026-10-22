//! The 64-byte seed a mnemonic and passphrase stretch into.

use std::fmt;

use crate::keys::wipe::Wipe;

/// A BIP-39 seed: the root of an EIP-2333 key tree.
///
/// The bytes are overwritten with zero on drop, and debug output hides them.
pub struct Seed {
    /// The PBKDF2-HMAC-SHA512 output.
    bytes: [u8; Self::LEN],
}

impl Seed {
    /// Bytes in a seed: 512 bits, per BIP-39, section "From mnemonic to seed".
    pub const LEN: usize = 64;

    /// Wraps seed bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self { bytes }
    }

    /// The seed bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.bytes
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.bytes.wipe();
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_bytes() {
        assert_eq!(
            format!("{:?}", Seed::from_bytes([7; 64])),
            "Seed(<redacted>)"
        );
    }
}
