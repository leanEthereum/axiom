//! The sponge construction over Keccak-f\[1600\], shared by every hash of the family.

use crate::keccak::KeccakF1600;

/// Bytes of the Keccak-f\[1600\] state.
pub(crate) const STATE_BYTES: usize = 200;

/// An absorbing sponge with a rate of RATE bytes.
///
/// # Invariants
///
/// The buffer holds the bytes of the current block not yet absorbed, always fewer than the rate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sponge<const RATE: usize> {
    /// The permutation state.
    state: KeccakF1600,
    /// Bytes of the current block not yet absorbed.
    buffer: [u8; RATE],
    /// How many bytes of the buffer are filled.
    filled: usize,
}

impl<const RATE: usize> Sponge<RATE> {
    /// A sponge over no bytes yet.
    pub(crate) const fn new() -> Self {
        // The rate leaves a non-empty capacity, and the state takes whole lanes.
        const {
            assert!(RATE > 0 && RATE < STATE_BYTES && RATE.is_multiple_of(8));
        }
        Self {
            state: KeccakF1600::new(),
            buffer: [0; RATE],
            filled: 0,
        }
    }

    /// Absorbs more bytes.
    pub(crate) fn absorb(&mut self, mut data: &[u8]) {
        // Phase 1: top up a partly filled buffer.
        if self.filled > 0 {
            let take = (RATE - self.filled).min(data.len());
            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < RATE {
                return;
            }
            self.state.absorb(&self.buffer);
            self.state.permute();
            self.filled = 0;
        }

        // Phase 2: absorb whole blocks straight from the input.
        let (blocks, tail) = data.as_chunks::<RATE>();
        for block in blocks {
            self.state.absorb(block);
            self.state.permute();
        }

        // Phase 3: keep the tail for the next call.
        self.buffer[..tail.len()].copy_from_slice(tail);
        self.filled = tail.len();
    }

    /// Pads the last block with a domain byte and returns the state ready to squeeze.
    ///
    /// # Algorithm
    ///
    /// The domain byte carries the suffix bits and the first bit of pad10*1, per FIPS 202, appendix B.2.
    ///
    /// ```text
    /// Keccak : 0x01 = pad bit only
    /// SHA-3  : 0x06 = suffix 01, then the pad bit
    /// SHAKE  : 0x1f = suffix 1111, then the pad bit
    /// ```
    ///
    /// The last bit of pad10*1 is 0x80 in the final byte of the block.
    /// With one free byte both share it.
    pub(crate) fn pad(mut self, domain: u8) -> KeccakF1600 {
        self.buffer[self.filled..].fill(0);
        self.buffer[self.filled] ^= domain;
        self.buffer[RATE - 1] ^= 0x80;
        self.state.absorb(&self.buffer);
        self.state.permute();
        self.state
    }
}
