//! The raw value of one record entry, decoded on demand.

use axiom_rlp::Decoder;
use axiom_ssz::Ssz;

/// The raw RLP of one record value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RawValue<'a>(pub(crate) &'a [u8]);

impl RawValue<'_> {
    /// The value as a string of exactly N bytes.
    pub(crate) fn array<const N: usize>(self) -> Option<[u8; N]> {
        // Exactly one RLP string of the right length.
        let mut decoder = Decoder::new(self.0);
        let bytes = decoder.array().ok()?;
        decoder.finish().ok()?;
        Some(bytes)
    }

    /// The value as a port: a canonical integer of at most 16 bits.
    pub(crate) fn port(self) -> Option<u16> {
        // Exactly one canonical RLP integer.
        let mut decoder = Decoder::new(self.0);
        let port = decoder.u16().ok()?;
        decoder.finish().ok()?;
        Some(port)
    }

    /// The value as an SSZ encoding held in an RLP string.
    pub(crate) fn ssz<T: Ssz>(self) -> Option<T> {
        // Exactly one RLP string, whose payload must be a strict SSZ encoding.
        let mut decoder = Decoder::new(self.0);
        let bytes = decoder.bytes().ok()?;
        decoder.finish().ok()?;
        T::decode(bytes).ok()
    }
}
