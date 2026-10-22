//! The sending half of a stream: bytes the owner wrote, until the peer acknowledges them.
//!
//! # Overview
//!
//! The buffer holds every byte from the lowest unacknowledged offset to the end written.
//! Three sets of offsets describe it:
//!
//! - bytes never sent, from the send cursor to the end
//! - bytes declared lost, waiting to go out again
//! - bytes acknowledged, which free the buffer front once contiguous
//!
//! Lost bytes go out before new ones, so a gap at the receiver closes first.
//! New bytes go out only below the peer's flow control limit, per RFC 9000, section 4.1.
//! The CRYPTO streams of each level use the same buffer, without flow control.

use std::collections::VecDeque;

use super::super::range_set::RangeSet;

/// One stretch of stream bytes chosen for a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Chunk {
    /// The offset of the first byte.
    pub(crate) offset: u64,
    /// Bytes in the chunk.
    pub(crate) len: usize,
    /// Whether the frame carries the FIN.
    pub(crate) fin: bool,
}

/// Bytes written to a stream and not yet acknowledged.
#[derive(Clone, Debug, Default)]
pub(crate) struct SendBuffer {
    /// Bytes from the base offset to the end written.
    data: VecDeque<u8>,
    /// The offset of the first byte held.
    base: u64,
    /// The lowest offset never sent.
    unsent: u64,
    /// Sent ranges declared lost.
    lost: RangeSet,
    /// Acknowledged ranges above the base.
    acked: RangeSet,
    /// Whether the owner finished the stream.
    finished: bool,
    /// Whether a frame carrying the FIN is in flight or acknowledged.
    fin_sent: bool,
    /// Whether the FIN was declared lost and must be sent again.
    fin_lost: bool,
    /// Whether the peer acknowledged the FIN.
    fin_acked: bool,
}

impl SendBuffer {
    /// Appends bytes to the stream.
    pub(crate) fn write(&mut self, bytes: &[u8]) {
        debug_assert!(!self.finished, "write after finish");
        self.data.extend(bytes);
    }

    /// Marks the end of the stream after the bytes written so far.
    pub(crate) const fn finish(&mut self) {
        self.finished = true;
    }

    /// Whether the owner finished the stream.
    pub(crate) const fn is_finished(&self) -> bool {
        self.finished
    }

    /// The offset one past the last byte written.
    pub(crate) fn end(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    /// Bytes held: written and not yet acknowledged as a contiguous prefix.
    pub(crate) fn buffered(&self) -> usize {
        self.data.len()
    }

    /// Bytes written but never sent.
    pub(crate) fn unsent_len(&self) -> u64 {
        self.end() - self.unsent
    }

    /// Whether every byte and the FIN, if any, are acknowledged.
    pub(crate) fn is_complete(&self) -> bool {
        self.finished && self.fin_acked && self.data.is_empty()
    }

    /// Whether something waits to be sent below a flow control limit.
    pub(crate) fn has_pending(&self, limit: u64) -> bool {
        !self.lost.is_empty() || (self.unsent < self.end() && self.unsent < limit) || self.fin_due()
    }

    /// Whether the FIN must go out in a frame of its own or with the last bytes.
    fn fin_due(&self) -> bool {
        self.finished && self.unsent == self.end() && (!self.fin_sent || self.fin_lost)
    }

    /// Chooses the next chunk to send, lost bytes first.
    ///
    /// # Arguments
    ///
    /// - `max_len`: the most bytes the frame can carry.
    /// - `limit`: the peer's flow control limit; lost bytes were sent before, so it does not bind them.
    ///
    /// # Returns
    ///
    /// The chunk, now counted as sent, or nothing when no byte and no FIN is due.
    pub(crate) fn next_chunk(&mut self, max_len: usize, limit: u64) -> Option<Chunk> {
        if let Some(range) = self.lost.pop_min() {
            let len = (range.end - range.start).min(max_len as u64);
            if range.start + len < range.end {
                self.lost.insert(range.start + len..range.end);
            }
            // A resent final chunk carries the FIN again when that was lost too.
            let fin = self.finished && range.start + len == self.end() && self.fin_lost;
            if fin {
                self.fin_lost = false;
            }
            return Some(Chunk {
                offset: range.start,
                // Invariant: len is at most max_len, a usize.
                len: len as usize,
                fin,
            });
        }
        let room = limit
            .saturating_sub(self.unsent)
            .min(self.end() - self.unsent);
        let len = room.min(max_len as u64);
        let fin =
            self.finished && self.unsent + len == self.end() && (!self.fin_sent || self.fin_lost);
        if len == 0 && !fin {
            return None;
        }
        let chunk = Chunk {
            offset: self.unsent,
            // Invariant: len is at most max_len, a usize.
            len: len as usize,
            fin,
        };
        self.unsent += len;
        if fin {
            self.fin_sent = true;
            self.fin_lost = false;
        }
        Some(chunk)
    }

    /// Copies a sent chunk's bytes into a frame.
    pub(crate) fn copy(&self, chunk: Chunk, out: &mut Vec<u8>) {
        // Invariant: a chunk returned by the buffer lies above the base, since acks only free acknowledged bytes.
        let start = (chunk.offset - self.base) as usize;
        let (front, back) = self.data.as_slices();
        let range = start..start + chunk.len;
        if range.end <= front.len() {
            out.extend_from_slice(&front[range]);
        } else if range.start >= front.len() {
            out.extend_from_slice(&back[range.start - front.len()..range.end - front.len()]);
        } else {
            out.extend_from_slice(&front[range.start..]);
            out.extend_from_slice(&back[..range.end - front.len()]);
        }
    }

    /// Records the acknowledgment of a chunk, freeing the buffer front when it becomes contiguous.
    pub(crate) fn on_acked(&mut self, chunk: Chunk) {
        let range = chunk.offset..chunk.offset + chunk.len as u64;
        if chunk.fin {
            self.fin_acked = true;
            self.fin_lost = false;
        }
        if range.is_empty() || range.end <= self.base {
            return;
        }
        self.acked.insert(range.start.max(self.base)..range.end);
        self.lost.remove(range);
        // Free the acknowledged prefix.
        if self.acked.min() == Some(self.base)
            && let Some(prefix) = self.acked.pop_min()
        {
            let freed = prefix.end - self.base;
            // Invariant: the freed prefix lies within the held bytes.
            self.data.drain(..freed as usize);
            self.base = prefix.end;
        }
    }

    /// Records the loss of a chunk, so its unacknowledged bytes go out again.
    pub(crate) fn on_lost(&mut self, chunk: Chunk) {
        let range = chunk.offset.max(self.base)..chunk.offset + chunk.len as u64;
        if !range.is_empty() {
            for gap in self.acked.gaps(range) {
                self.lost.insert(gap);
            }
        }
        if chunk.fin && !self.fin_acked {
            self.fin_lost = true;
        }
    }

    /// The range of bytes sent so far, for a reset's final size.
    pub(crate) const fn sent_end(&self) -> u64 {
        self.unsent
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn sends_new_bytes_under_the_limit_then_the_fin() {
        let mut buffer = SendBuffer::default();
        buffer.write(b"hello world");
        buffer.finish();

        // A limit of 5 lets "hello" out; the FIN waits for the rest.
        assert_eq!(
            buffer.next_chunk(100, 5),
            Some(Chunk {
                offset: 0,
                len: 5,
                fin: false
            })
        );
        assert_eq!(buffer.next_chunk(100, 5), None);
        assert!(!buffer.has_pending(5));

        // The limit rises to 100: the last 6 bytes go out with the FIN.
        assert_eq!(
            buffer.next_chunk(100, 100),
            Some(Chunk {
                offset: 5,
                len: 6,
                fin: true
            })
        );
        assert_eq!(buffer.next_chunk(100, 100), None);
        let mut out = Vec::new();
        buffer.copy(
            Chunk {
                offset: 5,
                len: 6,
                fin: true,
            },
            &mut out,
        );
        assert_eq!(out, b" world");
    }

    #[test]
    fn lost_bytes_go_first_and_acks_free_the_front() {
        let mut buffer = SendBuffer::default();
        buffer.write(&[7; 30]);
        let first = buffer.next_chunk(10, 100).unwrap();
        let second = buffer.next_chunk(10, 100).unwrap();
        let third = buffer.next_chunk(10, 100).unwrap();

        // The second chunk is lost and the third acknowledged.
        buffer.on_lost(second);
        buffer.on_acked(third);
        assert_eq!(buffer.acked.iter().collect::<Vec<_>>(), [20..30]);
        assert_eq!(
            buffer.next_chunk(4, 100),
            Some(Chunk {
                offset: 10,
                len: 4,
                fin: false
            })
        );

        // The first chunk's ack frees bytes 0..10 only: 10..20 are still unacknowledged.
        buffer.on_acked(first);
        assert_eq!(buffer.buffered(), 20);

        // A late ack of the lost chunk frees everything and cancels its retransmission.
        buffer.on_acked(second);
        assert_eq!(buffer.buffered(), 0);
        assert_eq!(buffer.next_chunk(10, 100), None);
    }

    #[test]
    fn a_lost_fin_is_sent_again() {
        let mut buffer = SendBuffer::default();
        buffer.finish();
        let fin = buffer.next_chunk(10, 0).unwrap();
        assert_eq!(
            fin,
            Chunk {
                offset: 0,
                len: 0,
                fin: true
            }
        );
        assert!(!buffer.has_pending(0));
        buffer.on_lost(fin);
        assert!(buffer.has_pending(0));
        assert_eq!(buffer.next_chunk(10, 0), Some(fin));
        buffer.on_acked(fin);
        assert!(buffer.is_complete());
    }

    proptest! {
        #[test]
        fn every_byte_arrives_despite_losses(
            data in proptest::collection::vec(any::<u8>(), 1..400),
            sizes in proptest::collection::vec(1_usize..50, 1..20),
            losses in proptest::collection::vec(any::<bool>(), 1..64),
        ) {
            // Send in frames of varying size; each frame is lost or acknowledged by the pattern.
            let mut buffer = SendBuffer::default();
            buffer.write(&data);
            buffer.finish();
            let mut received = vec![None; data.len()];
            let mut fin = false;
            let mut turn = 0;
            while !buffer.is_complete() {
                let size = sizes[turn % sizes.len()];
                let Some(chunk) = buffer.next_chunk(size, u64::MAX) else {
                    break;
                };
                let lose = losses[turn % losses.len()] && turn < 200;
                turn += 1;
                if lose {
                    buffer.on_lost(chunk);
                    continue;
                }
                let mut bytes = Vec::new();
                buffer.copy(chunk, &mut bytes);
                for (i, byte) in bytes.into_iter().enumerate() {
                    received[chunk.offset as usize + i] = Some(byte);
                }
                fin |= chunk.fin;
                buffer.on_acked(chunk);
            }
            prop_assert!(buffer.is_complete());
            prop_assert!(fin);
            let received: Vec<u8> = received.into_iter().map(|b| b.unwrap()).collect();
            prop_assert_eq!(received, data);
        }
    }
}
