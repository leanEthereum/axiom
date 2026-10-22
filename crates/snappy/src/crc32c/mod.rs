//! CRC-32C, the Castagnoli checksum that guards every framed Snappy chunk.

#[cfg(target_arch = "aarch64")]
mod aarch64_crc;
mod backend;
mod portable;
#[cfg(target_arch = "x86_64")]
mod x86_64_sse42;

use backend::Backend;

/// A running CRC-32C over bytes fed in any number of pieces.
///
/// # Overview
///
/// The checksum is the reflected CRC with polynomial 0x1EDC6F41, per RFC 3720.
/// The state starts at all ones and is inverted once at the end.
///
/// # Performance
///
/// On x86_64 with SSE4.2 and on aarch64 with the CRC extension, a hardware instruction does the work.
/// Elsewhere a slicing-by-8 table path handles 8 bytes per step.
/// The choice happens once per checksum, at run time.
/// Tests pin every path to the same values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Crc32c {
    /// Raw state: the inverted CRC of the bytes so far.
    state: u32,
    /// The implementation chosen for this CPU.
    backend: Backend,
}

impl Crc32c {
    /// A checksum over no bytes yet, on the fastest path the CPU supports.
    #[must_use]
    pub fn new() -> Self {
        Self::with_backend(Backend::detect())
    }

    /// A checksum over no bytes yet, on a chosen path.
    const fn with_backend(backend: Backend) -> Self {
        Self {
            state: u32::MAX,
            backend,
        }
    }

    /// The checksum of one byte string.
    #[must_use]
    pub fn checksum(bytes: &[u8]) -> u32 {
        let mut crc = Self::new();
        crc.update(bytes);
        crc.finish()
    }

    /// The checksum of bytes, masked as the snappy framing format stores it.
    ///
    /// Masking keeps checksums of data that itself holds checksums well distributed.
    #[must_use]
    pub fn masked(bytes: &[u8]) -> u32 {
        Self::mask(Self::checksum(bytes))
    }

    /// Masks a checksum.
    ///
    /// ```text
    ///     masked = rotate_right(crc, 15) + 0xa282ead8   (mod 2^32)
    /// ```
    pub(crate) const fn mask(crc: u32) -> u32 {
        crc.rotate_right(15).wrapping_add(0xa282_ead8)
    }

    /// Feeds more bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.state = self.backend.update(self.state, bytes);
    }

    /// The checksum of all bytes fed so far.
    ///
    /// The running state is left untouched, so feeding may continue.
    #[must_use]
    pub const fn finish(&self) -> u32 {
        !self.state
    }
}

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The checksum of the bytes on one path.
    fn checksum_on(backend: Backend, bytes: &[u8]) -> u32 {
        let mut crc = Crc32c::with_backend(backend);
        crc.update(bytes);
        crc.finish()
    }

    /// Random bytes, in lengths around the 8-byte step of every path, then long ones.
    fn data() -> impl Strategy<Value = Vec<u8>> {
        let lengths = prop_oneof![
            prop::sample::select(vec![0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65]),
            0_usize..5000,
        ];
        lengths.prop_flat_map(|len| prop::collection::vec(any::<u8>(), len))
    }

    #[test]
    fn check_value_of_the_standard_string() {
        // The catalogue check value of CRC-32C over the ASCII digits 1 to 9, on every path.
        for backend in Backend::supported() {
            assert_eq!(checksum_on(backend, b"123456789"), 0xe306_9283);
        }
    }

    #[test]
    fn rfc_3720_vectors() {
        // iSCSI test patterns, RFC 3720 appendix B.4: 32 bytes each, on every path.
        let ascending: Vec<u8> = (0..32).collect();
        let descending: Vec<u8> = (0..32).rev().collect();
        for backend in Backend::supported() {
            assert_eq!(checksum_on(backend, &[0; 32]), 0x8a91_36aa);
            assert_eq!(checksum_on(backend, &[0xff; 32]), 0x62a8_ab43);
            assert_eq!(checksum_on(backend, &ascending), 0x46dd_794e);
            assert_eq!(checksum_on(backend, &descending), 0x113f_db5c);
        }
    }

    #[test]
    fn empty_input_checksums_to_zero() {
        // All ones in, inverted out: nothing fed leaves zero.
        assert_eq!(Crc32c::checksum(&[]), 0);
        assert_eq!(Crc32c::default().finish(), 0);
    }

    proptest! {
        #[test]
        fn table_path_matches_the_bitwise_definition(
            bytes in prop::collection::vec(any::<u8>(), 0..300),
            state in any::<u32>(),
        ) {
            // Slicing-by-8 must equal the one-bit-at-a-time division from any state.
            prop_assert_eq!(portable::update(state, &bytes), portable::update_bitwise(state, &bytes));
        }

        #[test]
        fn every_path_matches_the_portable_path(
            data in data(),
            skew in 0_usize..8,
            state in any::<u32>(),
        ) {
            // Every length class and every start alignment: each path equals the reference.
            let bytes = &data[skew.min(data.len())..];
            let reference = portable::update(state, bytes);
            for backend in Backend::supported() {
                prop_assert_eq!(backend.update(state, bytes), reference);
            }
        }

        #[test]
        fn pieces_checksum_like_the_whole(
            bytes in prop::collection::vec(any::<u8>(), 0..500),
            split in any::<prop::sample::Index>(),
        ) {
            // Feeding in two pieces equals feeding at once.
            let at = split.index(bytes.len() + 1);
            let mut crc = Crc32c::new();
            crc.update(&bytes[..at]);
            crc.update(&bytes[at..]);
            prop_assert_eq!(crc.finish(), Crc32c::checksum(&bytes));
        }

        #[test]
        fn single_bit_flips_are_detected(
            bytes in prop::collection::vec(any::<u8>(), 1..300),
            bit in 0usize..2400,
        ) {
            // A CRC detects every single-bit error, at every position.
            let bit = bit % (bytes.len() * 8);
            let mut flipped = bytes.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            prop_assert_ne!(Crc32c::checksum(&flipped), Crc32c::checksum(&bytes));
        }
    }
}
