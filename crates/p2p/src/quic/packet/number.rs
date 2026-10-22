//! Packet numbers and their truncated wire form, per RFC 9000, section 17.1.

use std::fmt;

/// A packet number in one packet number space, below 2^62.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct PacketNumber(pub u64);

impl PacketNumber {
    /// Bytes of the truncated encoding a sender writes, from one to four.
    ///
    /// The encoding must cover twice the span of numbers the peer may not have seen.
    /// That span runs from the largest acknowledged number to this one.
    /// See RFC 9000, appendix A.2.
    #[must_use]
    pub(crate) fn encoded_len(self, largest_acked: Option<Self>) -> usize {
        let unacked = match largest_acked {
            Some(acked) => self.0.saturating_sub(acked.0),
            None => self.0 + 1,
        }
        .max(1);
        // Bits to represent 2 * unacked values: ceil(log2(2 * unacked)).
        let bits = u64::BITS - (2 * unacked - 1).leading_zeros();
        (bits as usize).div_ceil(8).clamp(1, 4)
    }

    /// The low bytes of the number, as the header carries them.
    #[must_use]
    pub(crate) const fn truncate(self, len: usize) -> u32 {
        // Invariant: len is 1 to 4, so the mask keeps at most 32 bits.
        (self.0 & ((1 << (8 * len)) - 1)) as u32
    }

    /// Recovers a full number from its truncated form.
    ///
    /// The candidate nearest the number after the largest one processed wins.
    /// See RFC 9000, appendix A.3.
    #[must_use]
    pub(crate) const fn decode(truncated: u32, len: usize, largest: Option<Self>) -> Self {
        let expected = match largest {
            Some(largest) => largest.0 + 1,
            None => 0,
        };
        let window = 1_u64 << (8 * len);
        let half = window / 2;
        let mask = window - 1;
        let candidate = (expected & !mask) | truncated as u64;
        // Both branches compare without wrapping: the second operand never exceeds the first.
        if candidate + half <= expected && candidate < (1 << 62) - window {
            return Self(candidate + window);
        }
        if candidate > expected + half && candidate >= window {
            return Self(candidate - window);
        }
        Self(candidate)
    }

    /// The next number.
    #[must_use]
    pub(crate) const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Debug for PacketNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn rfc_9000_appendix_a2_examples() {
        // Acknowledged 0xabe8b3, sending 0xac5c02: 29519 unacknowledged, 16 bits.
        let acked = Some(PacketNumber(0x00ab_e8b3));
        assert_eq!(PacketNumber(0x00ac_5c02).encoded_len(acked), 2);

        // Sending 0xace8fe in the same state needs 18 bits, so three bytes.
        assert_eq!(PacketNumber(0x00ac_e8fe).encoded_len(acked), 3);
    }

    #[test]
    fn rfc_9000_appendix_a3_example() {
        // Largest processed 0xa82f30ea; a 16-bit 0x9b32 decodes to 0xa82f9b32.
        let largest = Some(PacketNumber(0xa82f_30ea));
        assert_eq!(
            PacketNumber::decode(0x9b32, 2, largest),
            PacketNumber(0xa82f_9b32)
        );
    }

    #[test]
    fn first_packets() {
        // Nothing acknowledged: packet 0 takes one byte, packet 200 two.
        assert_eq!(PacketNumber(0).encoded_len(None), 1);
        assert_eq!(PacketNumber(127).encoded_len(None), 1);
        assert_eq!(PacketNumber(128).encoded_len(None), 2);

        // Nothing received yet: a truncated 2 is packet 2.
        assert_eq!(PacketNumber::decode(2, 4, None), PacketNumber(2));
    }

    #[test]
    fn decodes_across_the_window_edges() {
        // Expected 0x100: a one-byte 0xff is the packet just before, not 0x1ff.
        assert_eq!(
            PacketNumber::decode(0xff, 1, Some(PacketNumber(0xff))),
            PacketNumber(0xff)
        );
        // Expected 0x1f0: a one-byte 0x05 lies past the window edge, at 0x205.
        assert_eq!(
            PacketNumber::decode(0x05, 1, Some(PacketNumber(0x1ef))),
            PacketNumber(0x205)
        );
    }

    proptest! {
        #[test]
        fn sender_encoding_always_decodes(
            acked in 0_u64..1 << 40,
            ahead in 1_u64..1 << 20,
            behind in 0_u64..1 << 20,
        ) {
            // The receiver has processed some number at most the sender's span behind.
            let full = PacketNumber(acked + ahead);
            let len = full.encoded_len(Some(PacketNumber(acked)));
            let largest = PacketNumber(acked + behind.min(ahead - 1));
            let decoded = PacketNumber::decode(full.truncate(len), len, Some(largest));
            prop_assert_eq!(decoded, full);
        }
    }
}
