//! The per-space state of a connection: keys, packet numbers, and the CRYPTO streams.

use super::received::ReceivedPackets;
use crate::quic::{
    TransportError, TransportErrorCode,
    crypto::KeyPair,
    packet::PacketNumber,
    stream::{RecvBuffer, SendBuffer},
};

/// Handshake bytes a space buffers ahead of the next expected offset.
///
/// Threshold: a certificate flight is a few kilobytes; 64 KiB tolerates heavy reordering.
const MAX_CRYPTO_BUFFER: usize = 64 * 1024;

/// One packet number space.
#[derive(Debug, Default)]
pub(crate) struct PacketSpace {
    /// The packet protection keys; Initial and Handshake only, 1-RTT keys live apart.
    pub(crate) keys: Option<KeyPair>,
    /// The next packet number to send.
    pub(crate) next_number: PacketNumber,
    /// The largest number the peer acknowledged, for packet number truncation.
    pub(crate) largest_acked: Option<PacketNumber>,
    /// Handshake bytes to send.
    pub(crate) crypto_send: SendBuffer,
    /// Handshake bytes received.
    pub(crate) crypto_recv: RecvBuffer,
    /// Received packet numbers.
    pub(crate) received: ReceivedPackets,
    /// Ack-eliciting probes the probe timeout asked for.
    pub(crate) probes: u8,
    /// Whether the space's keys were discarded for good.
    pub(crate) discarded: bool,
}

impl PacketSpace {
    /// Takes the next packet number.
    pub(crate) const fn take_number(&mut self) -> PacketNumber {
        let number = self.next_number;
        self.next_number = number.next();
        number
    }

    /// Takes in CRYPTO data and returns the bytes now contiguous.
    ///
    /// # Errors
    ///
    /// Fails with CRYPTO_BUFFER_EXCEEDED when too much arrives ahead of a gap.
    pub(crate) fn on_crypto(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let end = offset + data.len() as u64;
        if end > self.crypto_recv.delivered() + MAX_CRYPTO_BUFFER as u64 {
            return Err(TransportError::new(
                TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
                format!(
                    "crypto data reaches {end}, more than {MAX_CRYPTO_BUFFER} bytes past offset {}",
                    self.crypto_recv.delivered()
                ),
            ));
        }
        self.crypto_recv.insert(offset, data, false)?;
        Ok(self.crypto_recv.take_ready())
    }

    /// Discards the space: its keys go, and nothing more is sent or accepted in it.
    pub(crate) fn discard(&mut self) {
        self.keys = None;
        self.discarded = true;
        self.probes = 0;
        self.crypto_send = SendBuffer::default();
    }

    /// Whether the space has keys to send with.
    pub(crate) const fn can_send(&self) -> bool {
        self.keys.is_some() && !self.discarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_reassembly_and_its_bound() {
        let mut space = PacketSpace::default();
        assert_eq!(space.on_crypto(5, b"world"), Ok(None));
        assert_eq!(
            space.on_crypto(0, b"hello"),
            Ok(Some(b"helloworld".to_vec()))
        );
        // 64 KiB past offset 10 is too far ahead.
        assert_eq!(
            space
                .on_crypto(10 + 65_536, b"x")
                .map_err(|error| error.code),
            Err(TransportErrorCode::CRYPTO_BUFFER_EXCEEDED)
        );
        assert_eq!(space.take_number(), PacketNumber(0));
        assert_eq!(space.take_number(), PacketNumber(1));
    }
}
