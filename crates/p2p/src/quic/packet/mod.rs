//! Packets: headers, packet numbers, and the assembly of outgoing packets.

mod header;
mod number;
mod plain;

pub(crate) use header::{FIXED_BIT, Header, LONG_FORM, LongType, ProtectedPacket, RETRY_TAG_LEN};
pub(crate) use number::PacketNumber;
pub(crate) use plain::PlainPacket;
