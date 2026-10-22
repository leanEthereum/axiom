//! The ACK frame: received packet numbers as descending ranges, per RFC 9000, section 19.3.

use std::ops::Range;

use super::super::{DecodeError, VarInt, range_set::RangeSet, reader::Reader};

/// Frame type of an ACK without ECN counts.
pub(crate) const ACK: u64 = 0x02;

/// Frame type of an ACK with ECN counts.
pub(crate) const ACK_ECN: u64 = 0x03;

/// An acknowledgment of received packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AckFrame {
    /// Acknowledged packet numbers, largest range first, each half-open.
    pub(crate) ranges: Vec<Range<u64>>,
    /// The encoded ack delay, before scaling by the peer's exponent.
    pub(crate) delay: u64,
    /// ECT(0), ECT(1) and CE counts, when the sender reports them.
    pub(crate) ecn: Option<[u64; 3]>,
}

impl AckFrame {
    /// An acknowledgment of the most recent ranges of a set, at most a given count.
    ///
    /// Older ranges beyond the count are omitted, as RFC 9000, section 13.2.4, permits.
    pub(crate) fn from_ranges(set: &RangeSet, delay: u64, max_ranges: usize) -> Option<Self> {
        let ranges: Vec<Range<u64>> = set.iter().rev().take(max_ranges.max(1)).collect();
        (!ranges.is_empty()).then_some(Self {
            ranges,
            delay,
            ecn: None,
        })
    }

    /// The largest acknowledged number.
    #[must_use]
    pub(crate) fn largest(&self) -> u64 {
        // Invariant: decoding and construction both refuse an empty range list.
        self.ranges.first().map_or(0, |range| range.end - 1)
    }

    /// Decodes the body that follows the type byte.
    pub(crate) fn decode(reader: &mut Reader<'_>, frame_type: u64) -> Result<Self, DecodeError> {
        let malformed = |rule| DecodeError::MalformedFrame { frame_type, rule };
        let largest = reader.varint()?.get();
        let delay = reader.varint()?.get();
        let count = reader.varint()?.get();
        // Each further range takes at least two bytes, which bounds the allocation.
        if count > reader.remaining() as u64 / 2 {
            return Err(malformed("range count exceeds the frame"));
        }
        let first = reader.varint()?.get();
        let Some(mut smallest) = largest.checked_sub(first) else {
            return Err(malformed("first range below packet zero"));
        };
        let mut ranges = Vec::with_capacity(1 + count as usize);
        ranges.push(smallest..largest + 1);
        for _ in 0..count {
            let gap = reader.varint()?.get();
            let len = reader.varint()?.get();
            // largest = previous_smallest - gap - 2; smallest = largest - len.
            let Some(top) = smallest.checked_sub(gap).and_then(|v| v.checked_sub(2)) else {
                return Err(malformed("gap below packet zero"));
            };
            let Some(bottom) = top.checked_sub(len) else {
                return Err(malformed("range below packet zero"));
            };
            ranges.push(bottom..top + 1);
            smallest = bottom;
        }
        let ecn = if frame_type == ACK_ECN {
            Some([
                reader.varint()?.get(),
                reader.varint()?.get(),
                reader.varint()?.get(),
            ])
        } else {
            None
        };
        Ok(Self { ranges, delay, ecn })
    }

    /// Appends the frame, type byte included.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let frame_type = if self.ecn.is_some() { ACK_ECN } else { ACK };
        out.push(frame_type as u8);
        let Some(first) = self.ranges.first() else {
            return;
        };
        VarInt::saturating(first.end - 1).encode(out);
        VarInt::saturating(self.delay).encode(out);
        VarInt::saturating(self.ranges.len() as u64 - 1).encode(out);
        VarInt::saturating(first.end - 1 - first.start).encode(out);
        let mut smallest = first.start;
        for range in &self.ranges[1..] {
            // gap = previous_smallest - largest - 2, len = largest - smallest.
            VarInt::saturating(smallest - (range.end - 1) - 2).encode(out);
            VarInt::saturating(range.end - 1 - range.start).encode(out);
            smallest = range.start;
        }
        if let Some(counts) = self.ecn {
            for count in counts {
                VarInt::saturating(count).encode(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;

    #[test]
    fn encodes_gaps_and_lengths() {
        // Received 0..=2, 5..=5, 7..=9: three ranges, largest 9.
        let mut set = RangeSet::new();
        set.insert(0..3);
        set.insert(5..6);
        set.insert(7..10);
        let frame = AckFrame::from_ranges(&set, 25, 8).unwrap();
        assert_eq!(frame.ranges, [7..10, 5..6, 0..3]);
        assert_eq!(frame.largest(), 9);

        let mut out = Vec::new();
        frame.encode(&mut out);
        // Type 2, largest 9, delay 25, two more ranges, first length 2.
        // Then gap 7 - 5 - 2 = 0 and length 0, then gap 5 - 2 - 2 = 1 and length 2.
        assert_eq!(out, [0x02, 9, 25, 2, 2, 0, 0, 1, 2]);

        let mut reader = Reader::new(&out[1..]);
        assert_eq!(AckFrame::decode(&mut reader, ACK), Ok(frame));
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn caps_the_range_count() {
        // Five ranges, at most two reported: the two most recent.
        let mut set = RangeSet::new();
        for start in [0, 10, 20, 30, 40] {
            set.insert(start..start + 2);
        }
        let frame = AckFrame::from_ranges(&set, 0, 2).unwrap();
        assert_eq!(frame.ranges, [40..42, 30..32]);
        assert_eq!(AckFrame::from_ranges(&RangeSet::new(), 0, 2), None);
    }

    #[test]
    fn refuses_ranges_below_zero() {
        // Largest 1 with a first range of 2 would reach packet -1.
        let mut reader = Reader::new(&[1, 0, 0, 2]);
        assert_eq!(
            AckFrame::decode(&mut reader, ACK),
            Err(DecodeError::MalformedFrame {
                frame_type: ACK,
                rule: "first range below packet zero"
            })
        );
        // Largest 5, first range 1 so smallest 4, then a gap of 3 would reach -1.
        let mut reader = Reader::new(&[5, 0, 1, 1, 3, 0]);
        assert_eq!(
            AckFrame::decode(&mut reader, ACK),
            Err(DecodeError::MalformedFrame {
                frame_type: ACK,
                rule: "gap below packet zero"
            })
        );
        // A range count of 200 in a frame of 4 bytes.
        let mut reader = Reader::new(&[5, 0, 0x40, 200, 0, 0]);
        assert_eq!(
            AckFrame::decode(&mut reader, ACK),
            Err(DecodeError::MalformedFrame {
                frame_type: ACK,
                rule: "range count exceeds the frame"
            })
        );
    }

    #[test]
    fn carries_ecn_counts() {
        let frame = AckFrame {
            ranges: iter::once(3..4).collect(),
            delay: 0,
            ecn: Some([1, 2, 3]),
        };
        let mut out = Vec::new();
        frame.encode(&mut out);
        assert_eq!(out, [0x03, 3, 0, 0, 0, 1, 2, 3]);
        assert_eq!(
            AckFrame::decode(&mut Reader::new(&out[1..]), ACK_ECN),
            Ok(frame)
        );
    }
}
