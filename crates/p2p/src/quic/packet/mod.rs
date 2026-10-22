//! Packets: headers, packet numbers, and the assembly of outgoing packets.

mod header;
mod number;

pub(crate) use header::{FIXED_BIT, LONG_FORM, RETRY_TAG_LEN};
pub use header::{Header, LongType, ProtectedPacket};
pub use number::PacketNumber;
