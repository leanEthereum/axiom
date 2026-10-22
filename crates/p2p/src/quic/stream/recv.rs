//! The receiving half of a stream: reassembly of bytes that arrive out of order.
//!
//! Bytes are delivered in order as soon as they are contiguous with what came before.
//! Out-of-order bytes wait, trimmed of anything already held, so duplicates cost nothing.
//! The final size rules of RFC 9000, section 4.5, are enforced here.

use std::collections::BTreeMap;

use super::super::{TransportError, TransportErrorCode, range_set::RangeSet};

/// Received bytes awaiting in-order delivery.
#[derive(Clone, Debug, Default)]
pub(crate) struct RecvBuffer {
    /// Bytes delivered so far: the in-order prefix.
    delivered: u64,
    /// Out-of-order chunks by offset, never overlapping.
    pending: BTreeMap<u64, Vec<u8>>,
    /// The ranges the pending chunks cover.
    held: RangeSet,
    /// Bytes held in pending chunks.
    pending_bytes: usize,
    /// The highest offset received, one past the last byte.
    highest: u64,
    /// The stream's final size, once a FIN or reset fixed it.
    final_size: Option<u64>,
}

impl RecvBuffer {
    /// The highest offset received, which counts against flow control.
    pub(crate) const fn highest(&self) -> u64 {
        self.highest
    }

    /// Bytes delivered in order.
    pub(crate) const fn delivered(&self) -> u64 {
        self.delivered
    }

    /// The final size, once known.
    pub(crate) const fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    /// Bytes waiting behind a gap.
    pub(crate) const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Whether every byte up to the final size has been delivered.
    pub(crate) fn is_finished(&self) -> bool {
        self.final_size == Some(self.delivered)
    }

    /// Takes in a chunk of the stream.
    ///
    /// # Errors
    ///
    /// Fails with FINAL_SIZE_ERROR when the chunk contradicts a known or claimed final size.
    pub(crate) fn insert(
        &mut self,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), TransportError> {
        let end = offset + data.len() as u64;
        self.check_final_size(end, fin)?;
        self.highest = self.highest.max(end);
        // Keep only the parts neither delivered nor already held.
        let start = offset.max(self.delivered);
        if start >= end {
            return Ok(());
        }
        for gap in self.held.gaps(start..end) {
            // Invariant: each gap lies inside offset..end, so the slice bounds hold.
            let slice = &data[(gap.start - offset) as usize..(gap.end - offset) as usize];
            self.pending.insert(gap.start, slice.to_vec());
            self.pending_bytes += slice.len();
            self.held.insert(gap);
        }
        Ok(())
    }

    /// Applies the final size rules to a chunk ending at an offset.
    fn check_final_size(&mut self, end: u64, fin: bool) -> Result<(), TransportError> {
        let error =
            |reason: &str| TransportError::new(TransportErrorCode::FINAL_SIZE_ERROR, reason);
        if let Some(final_size) = self.final_size {
            if end > final_size {
                return Err(error("data beyond the final size"));
            }
            if fin && end != final_size {
                return Err(error("final size changed"));
            }
        } else if fin {
            if end < self.highest {
                return Err(error("final size below data already received"));
            }
            self.final_size = Some(end);
        }
        Ok(())
    }

    /// Fixes the final size from a reset, checking it against what arrived.
    ///
    /// # Errors
    ///
    /// Fails with FINAL_SIZE_ERROR on a contradiction.
    pub(crate) fn reset(&mut self, final_size: u64) -> Result<(), TransportError> {
        self.check_final_size(final_size, true)?;
        self.highest = self.highest.max(final_size);
        self.pending.clear();
        self.held = RangeSet::new();
        self.pending_bytes = 0;
        Ok(())
    }

    /// Takes the bytes that became contiguous, if any.
    pub(crate) fn take_ready(&mut self) -> Option<Vec<u8>> {
        let mut ready: Option<Vec<u8>> = None;
        while let Some(entry) = self.pending.first_entry() {
            if *entry.key() != self.delivered {
                break;
            }
            let chunk = entry.remove();
            self.delivered += chunk.len() as u64;
            self.pending_bytes -= chunk.len();
            match &mut ready {
                Some(bytes) => bytes.extend_from_slice(&chunk),
                None => ready = Some(chunk),
            }
        }
        self.held.remove_below(self.delivered);
        ready
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn reorders_and_drops_duplicates() {
        let mut buffer = RecvBuffer::default();
        // "world" arrives first, at offset 6: nothing is ready.
        buffer.insert(6, b"world", true).unwrap();
        assert_eq!(buffer.take_ready(), None);
        assert_eq!(buffer.pending_bytes(), 5);

        // "hello " overlapping "w" arrives: both are ready, "w" counted once.
        buffer.insert(0, b"hello w", false).unwrap();
        assert_eq!(buffer.take_ready(), Some(b"hello world".to_vec()));
        assert!(buffer.is_finished());

        // A retransmission of delivered bytes changes nothing.
        buffer.insert(0, b"hello", false).unwrap();
        assert_eq!(buffer.take_ready(), None);
    }

    #[test]
    fn final_size_rules() {
        let error = |reason: &str| {
            Err(TransportError::new(
                TransportErrorCode::FINAL_SIZE_ERROR,
                reason,
            ))
        };

        // A FIN at 10, then data up to 12.
        let mut buffer = RecvBuffer::default();
        buffer.insert(0, &[0; 10], true).unwrap();
        assert_eq!(
            buffer.insert(10, &[0; 2], false),
            error("data beyond the final size")
        );
        assert_eq!(buffer.insert(0, &[0; 8], true), error("final size changed"));

        // Data up to 20, then a FIN at 15.
        let mut buffer = RecvBuffer::default();
        buffer.insert(10, &[0; 10], false).unwrap();
        assert_eq!(
            buffer.insert(10, &[0; 5], true),
            error("final size below data already received")
        );

        // A reset at 15 after data up to 20.
        assert_eq!(
            buffer.reset(15),
            error("final size below data already received")
        );
        assert_eq!(buffer.reset(25), Ok(()));
        assert_eq!(buffer.final_size(), Some(25));
        assert_eq!(buffer.highest(), 25);
    }

    proptest! {
        #[test]
        fn any_arrival_order_rebuilds_the_stream(
            data in proptest::collection::vec(any::<u8>(), 1..300),
            cuts in proptest::collection::vec(0_usize..300, 0..12),
            order in proptest::collection::vec(any::<u64>(), 0..40),
        ) {
            // Cut the stream into chunks, duplicate a few, and deliver in a scrambled order.
            let mut bounds: Vec<usize> = cuts.into_iter().filter(|c| *c < data.len()).collect();
            bounds.push(0);
            bounds.push(data.len());
            bounds.sort_unstable();
            bounds.dedup();
            let mut chunks: Vec<(usize, usize)> = bounds.windows(2).map(|w| (w[0], w[1])).collect();
            let extra: Vec<(usize, usize)> = chunks.iter().step_by(2).copied().collect();
            chunks.extend(extra);
            for (i, key) in order.iter().enumerate() {
                let j = (*key as usize) % chunks.len();
                let len = chunks.len();
                chunks.swap(i % len, j);
            }
            let mut buffer = RecvBuffer::default();
            let mut out = Vec::new();
            for (start, end) in chunks {
                buffer.insert(start as u64, &data[start..end], end == data.len()).unwrap();
                if let Some(ready) = buffer.take_ready() {
                    out.extend(ready);
                }
            }
            prop_assert_eq!(out, data);
            prop_assert!(buffer.is_finished());
            prop_assert_eq!(buffer.pending_bytes(), 0);
        }
    }
}
