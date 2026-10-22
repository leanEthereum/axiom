//! The listener side: accepting the first supported proposal.

use std::mem;

use super::{
    LIST, MAX_PROPOSALS, NOT_AVAILABLE, Negotiated, NegotiationError, PROTOCOL_HEADER,
    decode_message, encode_list, encode_message, encode_raw_message,
};

/// Answers proposals, echoing the first supported one.
#[derive(Clone, Debug)]
pub struct Listener {
    /// Protocols this side speaks.
    supported: Vec<String>,
    /// Whether the dialer's header has arrived.
    header_received: bool,
    /// Proposals answered so far.
    proposals: usize,
    /// Bytes waiting to be written.
    outbound: Vec<u8>,
    /// Bytes received but not yet parsed.
    inbound: Vec<u8>,
}

impl Listener {
    /// Starts answering, sending the header right away.
    pub fn new<I>(supported: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        let mut outbound = Vec::new();
        encode_message(PROTOCOL_HEADER, &mut outbound);
        Self {
            supported: supported.into_iter().map(Into::into).collect(),
            header_received: false,
            proposals: 0,
            outbound,
            inbound: Vec::new(),
        }
    }

    /// Takes the bytes to write to the stream.
    pub fn take_output(&mut self) -> Vec<u8> {
        mem::take(&mut self.outbound)
    }

    /// Feeds bytes read from the stream.
    ///
    /// # Returns
    ///
    /// The agreement once a supported proposal arrives, or nothing while none has.
    /// The echo that confirms it is already queued as output.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Option<Negotiated>, NegotiationError> {
        self.inbound.extend_from_slice(bytes);
        while let Some((text, consumed)) = decode_message(&self.inbound)? {
            // Phase 1: the dialer's header must come first.
            if !self.header_received {
                if text != PROTOCOL_HEADER {
                    return Err(NegotiationError::InvalidHeader(text.to_owned()));
                }
                self.header_received = true;
            }
            // Phase 2: a listing request gets every supported name.
            else if text == LIST {
                let body = encode_list(self.supported.iter().map(String::as_str));
                encode_raw_message(&body, &mut self.outbound);
            }
            // Phase 3: a supported proposal is echoed and settles the negotiation.
            else if self.supported.iter().any(|protocol| protocol == text) {
                let protocol = text.to_owned();
                encode_message(&protocol, &mut self.outbound);
                let remainder = self.inbound.split_off(consumed);
                return Ok(Some(Negotiated {
                    protocol,
                    remainder,
                }));
            }
            // Phase 4: anything else is refused, within a bounded patience.
            else {
                self.proposals += 1;
                if self.proposals > MAX_PROPOSALS {
                    return Err(NegotiationError::TooManyProposals);
                }
                encode_message(NOT_AVAILABLE, &mut self.outbound);
            }
            self.inbound.drain(..consumed);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::multistream::{Dialer, Lister};

    /// The wire form of one message.
    fn message(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_message(text, &mut out);
        out
    }

    #[test]
    fn transcript_with_one_refusal() {
        // Dialer prefers mplex, then yamux; the listener speaks only yamux.
        let mut dialer = Dialer::new(["/mplex/6.7.0", "/yamux/1.0.0"]).unwrap();
        let mut listener = Listener::new(["/yamux/1.0.0"]);

        // Flight 1, dialer → listener: header and first proposal, pipelined.
        //
        //     0x13 "/multistream/1.0.0\n"   19 bytes
        //     0x0d "/mplex/6.7.0\n"         13 bytes
        let flight = dialer.take_output();
        let mut expected = message("/multistream/1.0.0");
        expected.extend(message("/mplex/6.7.0"));
        assert_eq!(flight, expected);
        assert_eq!(flight[0], 0x13);

        // The listener refuses mplex: its output is its header, then "na".
        assert_eq!(listener.receive(&flight), Ok(None));
        let flight = listener.take_output();
        let mut expected = message("/multistream/1.0.0");
        expected.extend([0x03, b'n', b'a', b'\n']);
        assert_eq!(flight, expected);

        // The dialer falls back to yamux.
        assert_eq!(dialer.receive(&flight), Ok(None));
        let flight = dialer.take_output();
        assert_eq!(flight, message("/yamux/1.0.0"));

        // The listener accepts and echoes; trailing bytes belong to yamux.
        let mut with_data = flight;
        with_data.extend([0x00, 0x01]);
        let agreed = listener.receive(&with_data).unwrap().unwrap();
        assert_eq!(
            agreed,
            Negotiated {
                protocol: "/yamux/1.0.0".into(),
                remainder: vec![0x00, 0x01]
            }
        );

        // The dialer sees the echo and settles too.
        let echo = listener.take_output();
        let agreed = dialer.receive(&echo).unwrap().unwrap();
        assert_eq!(
            agreed,
            Negotiated {
                protocol: "/yamux/1.0.0".into(),
                remainder: vec![]
            }
        );
    }

    #[test]
    fn byte_at_a_time_delivery() {
        // Feed every flight one byte at a time: the state machines must buffer.
        let mut dialer = Dialer::new(["/meshsub/1.2.0"]).unwrap();
        let mut listener = Listener::new(["/meshsub/1.2.0"]);
        let mut agreed = None;
        for byte in dialer.take_output() {
            if let Some(done) = listener.receive(&[byte]).unwrap() {
                agreed = Some(done);
            }
        }
        assert_eq!(agreed.unwrap().protocol, "/meshsub/1.2.0");
        let mut agreed = None;
        for byte in listener.take_output() {
            if let Some(done) = dialer.receive(&[byte]).unwrap() {
                agreed = Some(done);
            }
        }
        assert_eq!(agreed.unwrap().protocol, "/meshsub/1.2.0");
    }

    #[test]
    fn no_common_protocol() {
        let mut dialer = Dialer::new(["/a"]).unwrap();
        let mut listener = Listener::new(["/b"]);
        listener.receive(&dialer.take_output()).unwrap();
        // The only proposal is refused, leaving nothing to try.
        assert_eq!(
            dialer.receive(&listener.take_output()),
            Err(NegotiationError::NoCommonProtocol)
        );
    }

    #[test]
    fn listing() {
        // ls answer: one message nesting "/a\n" and "/bb\n".
        //
        //     outer length 9 = [0x03 "/a\n"] (4) + [0x04 "/bb\n"] (5)
        //     plus the outer newline → prefix 0x0a
        let mut lister = Lister::new();
        let mut listener = Listener::new(["/a", "/bb"]);
        assert_eq!(listener.receive(&lister.take_output()), Ok(None));
        let answer = listener.take_output();
        let header_len = message(PROTOCOL_HEADER).len();
        assert_eq!(
            &answer[header_len..],
            &[
                0x0a, 0x03, b'/', b'a', b'\n', 0x04, b'/', b'b', b'b', b'\n', b'\n'
            ]
        );
        assert_eq!(
            lister.receive(&answer),
            Ok(Some(vec!["/a".to_owned(), "/bb".to_owned()]))
        );
    }

    #[test]
    fn rejects_protocol_violations() {
        // A wrong header.
        let mut listener = Listener::new(["/a"]);
        assert_eq!(
            listener.receive(&message("/multistream/2.0.0")),
            Err(NegotiationError::InvalidHeader("/multistream/2.0.0".into()))
        );
        // A message without its newline: length 2, body "na".
        let mut dialer = Dialer::new(["/a"]).unwrap();
        assert_eq!(
            dialer.receive(&[0x02, b'n', b'a']),
            Err(NegotiationError::MissingNewline)
        );
        // An answer that is neither echo nor refusal.
        let mut dialer = Dialer::new(["/a"]).unwrap();
        let mut flight = message(PROTOCOL_HEADER);
        flight.extend(message("/b"));
        assert_eq!(
            dialer.receive(&flight),
            Err(NegotiationError::UnexpectedResponse("/b".into()))
        );
        // An empty proposal list.
        assert_eq!(
            Dialer::new(Vec::<String>::new()).err(),
            Some(NegotiationError::NothingToPropose)
        );
    }

    #[test]
    fn listener_patience_is_bounded() {
        let mut listener = Listener::new(["/a"]);
        let mut flight = message(PROTOCOL_HEADER);
        // 33 refused proposals exceed the bound of 32.
        for _ in 0..33 {
            flight.extend(message("/nope"));
        }
        assert_eq!(
            listener.receive(&flight),
            Err(NegotiationError::TooManyProposals)
        );
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = Listener::new(["/a"]).receive(&bytes);
            let _ = Dialer::new(["/a"]).unwrap().receive(&bytes);
            let _ = Lister::new().receive(&bytes);
        }

        #[test]
        fn negotiation_agrees_on_the_first_shared_protocol(
            dialer_set in proptest::collection::vec("/[a-z]{1,4}", 1..5),
            listener_set in proptest::collection::vec("/[a-z]{1,4}", 0..5),
        ) {
            // Run both state machines to completion over a lossless pipe.
            let mut dialer = Dialer::new(dialer_set.clone()).unwrap();
            let mut listener = Listener::new(listener_set.clone());
            let expected = dialer_set.iter().find(|p| listener_set.contains(p)).cloned();
            let mut outcome = None;
            for _ in 0..16 {
                if let Some(done) = listener.receive(&dialer.take_output()).unwrap() {
                    prop_assert_eq!(Some(&done.protocol), expected.as_ref());
                }
                match dialer.receive(&listener.take_output()) {
                    Ok(Some(done)) => { outcome = Some(Ok(done.protocol)); break; }
                    Ok(None) => {}
                    Err(error) => { outcome = Some(Err(error)); break; }
                }
            }
            match expected {
                Some(protocol) => prop_assert_eq!(outcome, Some(Ok(protocol))),
                None => prop_assert_eq!(outcome, Some(Err(NegotiationError::NoCommonProtocol))),
            }
        }
    }
}
