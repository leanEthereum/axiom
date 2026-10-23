//! The NewSessionTicket message, per RFC 8446, section 4.6.1.

use crate::{
    ProtocolError,
    codec::{Reader, Width},
};

/// A resumption ticket, which this stack checks and discards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NewSessionTicket;

impl NewSessionTicket {
    /// Checks the structure of a NewSessionTicket body, which this stack then discards.
    ///
    /// ```text
    /// ticket_lifetime: u32, ticket_age_add: u32, ticket_nonce <0..255>,
    /// ticket <1..2^16-1>, extensions <0..2^16-2>
    /// ```
    ///
    /// Resumption is never offered, so a ticket is useless here, yet a server may send one.
    pub(crate) fn check(body: &[u8]) -> Result<(), ProtocolError> {
        let mut reader = Reader::new(body);
        reader.bytes(8)?;
        reader.vector(Width::U8, 0, 0xff, 1)?;
        reader.vector(Width::U16, 1, 0xffff, 1)?;
        reader.vector(Width::U16, 0, 0xfffe, 1)?;
        reader.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tickets_are_checked_then_ignored() {
        // Lifetime and age add, an empty nonce, a 1-byte ticket, no extensions.
        let mut ticket = vec![0; 8];
        ticket.extend([0x00, 0x00, 0x01, 0xaa, 0x00, 0x00]);
        assert_eq!(NewSessionTicket::check(&ticket), Ok(()));

        // Mutation: an empty ticket.
        ticket[10] = 0x00;
        ticket.remove(11);
        assert_eq!(
            NewSessionTicket::check(&ticket),
            Err(ProtocolError::InvalidVectorLength {
                length: 0,
                min: 1,
                max: 0xffff,
                item: 1
            })
        );
    }
}
