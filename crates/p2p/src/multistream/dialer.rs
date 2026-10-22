//! The dialer side: proposing protocols until one is accepted.

use std::{collections::VecDeque, mem};

use super::{
    LIST, NOT_AVAILABLE, Negotiated, NegotiationError, PROTOCOL_HEADER, decode_list,
    decode_message, decode_raw_message, encode_message,
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
    /// Whether the listener's header has arrived.
    header_received: bool,
    /// Bytes waiting to be written.
    outbound: Vec<u8>,
    /// Bytes received but not yet parsed.
    inbound: Vec<u8>,
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
        let mut outbound = Vec::new();
        encode_message(PROTOCOL_HEADER, &mut outbound);
        encode_message(&proposed, &mut outbound);
        Ok(Self {
            remaining,
            proposed,
            header_received: false,
            outbound,
            inbound: Vec::new(),
        })
    }

    /// Takes the bytes to write to the stream.
    pub fn take_output(&mut self) -> Vec<u8> {
        mem::take(&mut self.outbound)
    }

    /// Feeds bytes read from the stream.
    ///
    /// # Returns
    ///
    /// The agreement once the listener echoes a proposal, or nothing while it is pending.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Option<Negotiated>, NegotiationError> {
        self.inbound.extend_from_slice(bytes);
        // Process every complete message in the buffer.
        while let Some((text, consumed)) = decode_message(&self.inbound)? {
            // Phase 1: the listener's header must come first.
            if !self.header_received {
                if text != PROTOCOL_HEADER {
                    return Err(NegotiationError::InvalidHeader(text.to_owned()));
                }
                self.header_received = true;
            }
            // Phase 2: an echo of the proposal settles the negotiation.
            else if text == self.proposed {
                let protocol = mem::take(&mut self.proposed);
                let remainder = self.inbound.split_off(consumed);
                return Ok(Some(Negotiated {
                    protocol,
                    remainder,
                }));
            }
            // Phase 3: a refusal moves on to the next proposal.
            else if text == NOT_AVAILABLE {
                self.proposed = self
                    .remaining
                    .pop_front()
                    .ok_or(NegotiationError::NoCommonProtocol)?;
                encode_message(&self.proposed, &mut self.outbound);
            } else {
                return Err(NegotiationError::UnexpectedResponse(text.to_owned()));
            }
            self.inbound.drain(..consumed);
        }
        Ok(None)
    }
}

/// Asks a listener for every protocol it supports.
#[derive(Clone, Debug, Default)]
pub struct Lister {
    /// Whether the listener's header has arrived.
    header_received: bool,
    /// Bytes waiting to be written.
    outbound: Vec<u8>,
    /// Bytes received but not yet parsed.
    inbound: Vec<u8>,
}

impl Lister {
    /// Starts a listing request.
    #[must_use]
    pub fn new() -> Self {
        let mut outbound = Vec::new();
        encode_message(PROTOCOL_HEADER, &mut outbound);
        encode_message(LIST, &mut outbound);
        Self {
            header_received: false,
            outbound,
            inbound: Vec::new(),
        }
    }

    /// Takes the bytes to write to the stream.
    pub fn take_output(&mut self) -> Vec<u8> {
        mem::take(&mut self.outbound)
    }

    /// Feeds bytes read from the stream, returning the list once it is complete.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Option<Vec<String>>, NegotiationError> {
        self.inbound.extend_from_slice(bytes);
        // The header arrives first, as text.
        if !self.header_received {
            let Some((text, consumed)) = decode_message(&self.inbound)? else {
                return Ok(None);
            };
            if text != PROTOCOL_HEADER {
                return Err(NegotiationError::InvalidHeader(text.to_owned()));
            }
            self.header_received = true;
            self.inbound.drain(..consumed);
        }
        // The answer is one message whose body nests one message per protocol.
        match decode_raw_message(&self.inbound)? {
            Some((body, _)) => decode_list(body).map(Some),
            None => Ok(None),
        }
    }
}
