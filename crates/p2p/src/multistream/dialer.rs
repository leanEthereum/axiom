//! The dialer side: proposing protocols until one is accepted.

use std::{collections::VecDeque, mem};

use super::{
    LIST, NOT_AVAILABLE, Negotiated, NegotiationError,
    message::{MessageReader, MessageWriter},
};

/// Proposes protocols in preference order until the listener accepts one.
///
/// The header and the first proposal leave together, saving a round trip.
#[derive(Clone, Debug)]
pub struct Dialer {
    /// Proposals not yet sent, most preferred first.
    remaining: VecDeque<String>,
    /// The proposal awaiting an answer.
    proposed: String,
    /// Messages waiting to be written.
    outbound: MessageWriter,
    /// Messages received, header first.
    inbound: MessageReader,
}

impl Dialer {
    /// Starts a negotiation over protocols in preference order.
    pub fn new<I>(protocols: I) -> Result<Self, NegotiationError>
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        let mut remaining: VecDeque<String> = protocols.into_iter().map(Into::into).collect();
        let proposed = remaining
            .pop_front()
            .ok_or(NegotiationError::NothingToPropose)?;
        // Pipeline the header and the first proposal into one write.
        let mut outbound = MessageWriter::with_header();
        outbound.push(&proposed);
        Ok(Self {
            remaining,
            proposed,
            outbound,
            inbound: MessageReader::new(),
        })
    }

    /// Takes the bytes to write to the stream.
    pub fn take_output(&mut self) -> Vec<u8> {
        self.outbound.take()
    }

    /// Feeds bytes read from the stream.
    ///
    /// # Returns
    ///
    /// The agreement once the listener echoes a proposal, or nothing while it is pending.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Option<Negotiated>, NegotiationError> {
        self.inbound.feed(bytes);
        // Process every complete message after the listener's header.
        while let Some(text) = self.inbound.next_text()? {
            // Phase 1: an echo of the proposal settles the negotiation.
            if text == self.proposed {
                let protocol = mem::take(&mut self.proposed);
                let remainder = self.inbound.take_remainder();
                return Ok(Some(Negotiated {
                    protocol,
                    remainder,
                }));
            }
            // Phase 2: a refusal moves on to the next proposal.
            if text != NOT_AVAILABLE {
                return Err(NegotiationError::UnexpectedResponse(text.to_owned()));
            }
            self.proposed = self
                .remaining
                .pop_front()
                .ok_or(NegotiationError::NoCommonProtocol)?;
            self.outbound.push(&self.proposed);
        }
        Ok(None)
    }
}

/// Asks a listener for every protocol it supports.
#[derive(Clone, Debug)]
pub struct Lister {
    /// Messages waiting to be written.
    outbound: MessageWriter,
    /// Messages received, header first.
    inbound: MessageReader,
}

impl Lister {
    /// Starts a listing request.
    #[must_use]
    pub fn new() -> Self {
        let mut outbound = MessageWriter::with_header();
        outbound.push(LIST);
        Self {
            outbound,
            inbound: MessageReader::new(),
        }
    }

    /// Takes the bytes to write to the stream.
    pub fn take_output(&mut self) -> Vec<u8> {
        self.outbound.take()
    }

    /// Feeds bytes read from the stream, returning the list once it is complete.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Option<Vec<String>>, NegotiationError> {
        self.inbound.feed(bytes);
        // The answer is one message whose body nests one message per protocol.
        match self.inbound.next_body()? {
            Some(body) => MessageReader::parse_list(body).map(Some),
            None => Ok(None),
        }
    }
}

impl Default for Lister {
    fn default() -> Self {
        Self::new()
    }
}
