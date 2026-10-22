//! Transport parameters: each side's limits, exchanged inside the TLS handshake.
//!
//! The encoding is a sequence of id, length, value triples, per RFC 9000, section 18.
//! Unknown ids are ignored, which lets future extensions and GREASE values pass.

use std::time::Duration;

use super::{ConnectionId, DecodeError, Side, VarInt, frame::RESET_TOKEN_LEN, reader::Reader};

/// Parameter ids of RFC 9000, section 18.2.
mod ids {
    pub(super) const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    pub(super) const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub(super) const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub(super) const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub(super) const INITIAL_MAX_DATA: u64 = 0x04;
    pub(super) const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub(super) const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub(super) const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub(super) const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub(super) const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub(super) const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub(super) const MAX_ACK_DELAY: u64 = 0x0b;
    pub(super) const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub(super) const PREFERRED_ADDRESS: u64 = 0x0d;
    pub(super) const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub(super) const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    pub(super) const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
}

/// The smallest UDP payload a peer may claim to accept, per RFC 9000, section 18.2.
const MIN_UDP_PAYLOAD_SIZE: u64 = 1200;

/// The largest ack delay exponent, per RFC 9000, section 18.2.
const MAX_ACK_DELAY_EXPONENT: u64 = 20;

/// The bound on max_ack_delay: values of 2^14 milliseconds or more are invalid.
const MAX_ACK_DELAY_BOUND: u64 = 1 << 14;

/// The largest stream count a peer may grant, 2^60.
const MAX_STREAMS: u64 = 1 << 60;

/// One side's transport parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransportParameters {
    /// The client's first destination id; servers only.
    pub(crate) original_destination_connection_id: Option<ConnectionId>,
    /// Idle time after which the sender closes silently; zero disables it.
    pub(crate) max_idle_timeout: Duration,
    /// The stateless reset token of the handshake connection id; servers only.
    pub(crate) stateless_reset_token: Option<[u8; RESET_TOKEN_LEN]>,
    /// The largest UDP payload the sender accepts.
    pub(crate) max_udp_payload_size: u64,
    /// The connection-wide receive limit.
    pub(crate) initial_max_data: u64,
    /// The receive limit of streams the sender opens.
    pub(crate) initial_max_stream_data_bidi_local: u64,
    /// The receive limit of bidirectional streams the peer opens.
    pub(crate) initial_max_stream_data_bidi_remote: u64,
    /// The receive limit of unidirectional streams the peer opens.
    pub(crate) initial_max_stream_data_uni: u64,
    /// Bidirectional streams the peer may open.
    pub(crate) initial_max_streams_bidi: u64,
    /// Unidirectional streams the peer may open.
    pub(crate) initial_max_streams_uni: u64,
    /// The exponent that scales the sender's ack delay field.
    pub(crate) ack_delay_exponent: u64,
    /// The longest the sender delays an acknowledgment.
    pub(crate) max_ack_delay: Duration,
    /// Whether the sender refuses connection migration.
    pub(crate) disable_active_migration: bool,
    /// Whether a preferred address was offered; servers only, and never used here.
    pub(crate) preferred_address: bool,
    /// How many connection ids the sender stores.
    pub(crate) active_connection_id_limit: u64,
    /// The source id of the sender's first packet.
    pub(crate) initial_source_connection_id: Option<ConnectionId>,
    /// The source id of the server's Retry; servers only.
    pub(crate) retry_source_connection_id: Option<ConnectionId>,
}

impl Default for TransportParameters {
    /// The values an absent parameter takes, per RFC 9000, section 18.2.
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: Duration::ZERO,
            stateless_reset_token: None,
            max_udp_payload_size: 65_527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            disable_active_migration: false,
            preferred_address: false,
            active_connection_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
        }
    }
}

impl TransportParameters {
    /// Decodes the peer's parameters and checks the rules RFC 9000, section 18.2, sets.
    ///
    /// # Arguments
    ///
    /// - `bytes`: the extension body.
    /// - `sender`: which side sent them, since some parameters are the server's alone.
    ///
    /// # Errors
    ///
    /// Fails on a malformed or duplicate parameter, a value out of range, or a misplaced one.
    pub(crate) fn decode(bytes: &[u8], sender: Side) -> Result<Self, DecodeError> {
        let mut params = Self::default();
        let mut seen = Vec::new();
        let mut reader = Reader::new(bytes);
        while !reader.is_empty() {
            let id = reader.varint()?.get();
            let value = reader.length_prefixed()?;
            let invalid = |rule| DecodeError::TransportParameter { id, rule };
            if seen.contains(&id) {
                return Err(invalid("duplicate parameter"));
            }
            seen.push(id);
            let server_only = matches!(
                id,
                ids::ORIGINAL_DESTINATION_CONNECTION_ID
                    | ids::STATELESS_RESET_TOKEN
                    | ids::PREFERRED_ADDRESS
                    | ids::RETRY_SOURCE_CONNECTION_ID
            );
            if server_only && sender == Side::Client {
                return Err(invalid("a client may not send it"));
            }
            match id {
                ids::ORIGINAL_DESTINATION_CONNECTION_ID => {
                    params.original_destination_connection_id = Some(ConnectionId::new(value)?);
                }
                ids::MAX_IDLE_TIMEOUT => {
                    params.max_idle_timeout = Duration::from_millis(Self::integer(id, value)?);
                }
                ids::STATELESS_RESET_TOKEN => {
                    let token = value
                        .try_into()
                        .map_err(|_| invalid("reset token is not 16 bytes"))?;
                    params.stateless_reset_token = Some(token);
                }
                ids::MAX_UDP_PAYLOAD_SIZE => {
                    params.max_udp_payload_size = Self::integer(id, value)?;
                    if params.max_udp_payload_size < MIN_UDP_PAYLOAD_SIZE {
                        return Err(invalid("below 1200 bytes"));
                    }
                }
                ids::INITIAL_MAX_DATA => params.initial_max_data = Self::integer(id, value)?,
                ids::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    params.initial_max_stream_data_bidi_local = Self::integer(id, value)?;
                }
                ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    params.initial_max_stream_data_bidi_remote = Self::integer(id, value)?;
                }
                ids::INITIAL_MAX_STREAM_DATA_UNI => {
                    params.initial_max_stream_data_uni = Self::integer(id, value)?;
                }
                ids::INITIAL_MAX_STREAMS_BIDI | ids::INITIAL_MAX_STREAMS_UNI => {
                    let count = Self::integer(id, value)?;
                    if count > MAX_STREAMS {
                        return Err(invalid("stream count above 2^60"));
                    }
                    if id == ids::INITIAL_MAX_STREAMS_BIDI {
                        params.initial_max_streams_bidi = count;
                    } else {
                        params.initial_max_streams_uni = count;
                    }
                }
                ids::ACK_DELAY_EXPONENT => {
                    params.ack_delay_exponent = Self::integer(id, value)?;
                    if params.ack_delay_exponent > MAX_ACK_DELAY_EXPONENT {
                        return Err(invalid("ack delay exponent above 20"));
                    }
                }
                ids::MAX_ACK_DELAY => {
                    let millis = Self::integer(id, value)?;
                    if millis >= MAX_ACK_DELAY_BOUND {
                        return Err(invalid("max ack delay of 2^14 ms or more"));
                    }
                    params.max_ack_delay = Duration::from_millis(millis);
                }
                ids::DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return Err(invalid("disable_active_migration carries a value"));
                    }
                    params.disable_active_migration = true;
                }
                ids::PREFERRED_ADDRESS => {
                    // Addresses, a connection id and a token: at least 41 bytes.
                    if value.len() < 41 {
                        return Err(invalid("preferred address too short"));
                    }
                    params.preferred_address = true;
                }
                ids::ACTIVE_CONNECTION_ID_LIMIT => {
                    params.active_connection_id_limit = Self::integer(id, value)?;
                    if params.active_connection_id_limit < 2 {
                        return Err(invalid("active connection id limit below 2"));
                    }
                }
                ids::INITIAL_SOURCE_CONNECTION_ID => {
                    params.initial_source_connection_id = Some(ConnectionId::new(value)?);
                }
                ids::RETRY_SOURCE_CONNECTION_ID => {
                    params.retry_source_connection_id = Some(ConnectionId::new(value)?);
                }
                // Unknown parameters, GREASE included, are ignored.
                _ => {}
            }
        }
        Ok(params)
    }

    /// A parameter value that must be exactly one varint.
    fn integer(id: u64, value: &[u8]) -> Result<u64, DecodeError> {
        let mut reader = Reader::new(value);
        let integer = reader
            .varint()
            .map_err(|_| DecodeError::TransportParameter {
                id,
                rule: "value is not a varint",
            })?;
        if !reader.is_empty() {
            return Err(DecodeError::TransportParameter {
                id,
                rule: "trailing bytes after the varint",
            });
        }
        Ok(integer.get())
    }

    /// Encodes the parameters, skipping those at their default.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let defaults = Self::default();
        let mut out = Vec::new();
        let bytes = |id: u64, value: &[u8], out: &mut Vec<u8>| {
            VarInt::saturating(id).encode(out);
            VarInt::saturating(value.len() as u64).encode(out);
            out.extend_from_slice(value);
        };
        let integer = |id: u64, value: u64, out: &mut Vec<u8>| {
            let mut encoded = Vec::with_capacity(8);
            VarInt::saturating(value).encode(&mut encoded);
            bytes(id, &encoded, out);
        };
        if let Some(id) = &self.original_destination_connection_id {
            bytes(
                ids::ORIGINAL_DESTINATION_CONNECTION_ID,
                id.as_bytes(),
                &mut out,
            );
        }
        if !self.max_idle_timeout.is_zero() {
            let millis = u64::try_from(self.max_idle_timeout.as_millis()).unwrap_or(u64::MAX);
            integer(ids::MAX_IDLE_TIMEOUT, millis, &mut out);
        }
        if let Some(token) = &self.stateless_reset_token {
            bytes(ids::STATELESS_RESET_TOKEN, token, &mut out);
        }
        let integers = [
            (
                ids::MAX_UDP_PAYLOAD_SIZE,
                self.max_udp_payload_size,
                defaults.max_udp_payload_size,
            ),
            (ids::INITIAL_MAX_DATA, self.initial_max_data, 0),
            (
                ids::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
                0,
            ),
            (
                ids::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
                0,
            ),
            (
                ids::INITIAL_MAX_STREAM_DATA_UNI,
                self.initial_max_stream_data_uni,
                0,
            ),
            (
                ids::INITIAL_MAX_STREAMS_BIDI,
                self.initial_max_streams_bidi,
                0,
            ),
            (
                ids::INITIAL_MAX_STREAMS_UNI,
                self.initial_max_streams_uni,
                0,
            ),
            (
                ids::ACK_DELAY_EXPONENT,
                self.ack_delay_exponent,
                defaults.ack_delay_exponent,
            ),
            (
                ids::MAX_ACK_DELAY,
                u64::try_from(self.max_ack_delay.as_millis()).unwrap_or(u64::MAX),
                25,
            ),
            (
                ids::ACTIVE_CONNECTION_ID_LIMIT,
                self.active_connection_id_limit,
                defaults.active_connection_id_limit,
            ),
        ];
        for (id, value, default) in integers {
            if value != default {
                integer(id, value, &mut out);
            }
        }
        if self.disable_active_migration {
            bytes(ids::DISABLE_ACTIVE_MIGRATION, &[], &mut out);
        }
        if let Some(id) = &self.initial_source_connection_id {
            bytes(ids::INITIAL_SOURCE_CONNECTION_ID, id.as_bytes(), &mut out);
        }
        if let Some(id) = &self.retry_source_connection_id {
            bytes(ids::RETRY_SOURCE_CONNECTION_ID, id.as_bytes(), &mut out);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::quic::testing::hex;

    #[test]
    fn decodes_the_rfc_9001_client_parameters() {
        // The quic_transport_parameters extension body of the RFC 9001, appendix A.2, ClientHello.
        let bytes = hex(concat!(
            "0408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f08",
            "8394c8f03e51570806048000ffff",
        ));
        let params = TransportParameters::decode(&bytes, Side::Client).unwrap();
        assert_eq!(
            params,
            TransportParameters {
                initial_max_data: (1 << 62) - 1,
                initial_max_stream_data_bidi_local: 0xffff,
                initial_max_stream_data_uni: 0xffff,
                initial_max_streams_bidi: 16,
                max_idle_timeout: Duration::from_millis(30_000),
                initial_max_streams_uni: 16,
                initial_source_connection_id: Some(
                    ConnectionId::new(&hex("8394c8f03e515708")).unwrap()
                ),
                initial_max_stream_data_bidi_remote: 0xffff,
                ..TransportParameters::default()
            }
        );
    }

    #[test]
    fn round_trips_every_field() {
        let params = TransportParameters {
            original_destination_connection_id: Some(ConnectionId::new(&[1; 8]).unwrap()),
            max_idle_timeout: Duration::from_secs(30),
            stateless_reset_token: Some([7; 16]),
            max_udp_payload_size: 1452,
            initial_max_data: 1 << 24,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 256,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 4,
            max_ack_delay: Duration::from_millis(20),
            disable_active_migration: true,
            preferred_address: false,
            active_connection_id_limit: 4,
            initial_source_connection_id: Some(ConnectionId::new(&[2; 8]).unwrap()),
            retry_source_connection_id: Some(ConnectionId::new(&[3; 8]).unwrap()),
        };
        assert_eq!(
            TransportParameters::decode(&params.encode(), Side::Server),
            Ok(params)
        );
    }

    #[test]
    fn enforces_the_rules() {
        let check = |bytes: &[u8], sender, id, rule| {
            assert_eq!(
                TransportParameters::decode(bytes, sender),
                Err(DecodeError::TransportParameter { id, rule })
            );
        };
        // A client may not send the original destination id.
        check(
            &[0x00, 0x01, 0xaa],
            Side::Client,
            0x00,
            "a client may not send it",
        );
        // max_udp_payload_size of 1199.
        check(
            &[0x03, 0x02, 0x44, 0xaf],
            Side::Server,
            0x03,
            "below 1200 bytes",
        );
        // ack_delay_exponent of 21.
        check(
            &[0x0a, 0x01, 21],
            Side::Server,
            0x0a,
            "ack delay exponent above 20",
        );
        // max_ack_delay of 2^14 ms.
        check(
            &[0x0b, 0x04, 0x80, 0x00, 0x40, 0x00],
            Side::Server,
            0x0b,
            "max ack delay of 2^14 ms or more",
        );
        // active_connection_id_limit of 1.
        check(
            &[0x0e, 0x01, 1],
            Side::Client,
            0x0e,
            "active connection id limit below 2",
        );
        // The same parameter twice.
        check(
            &[0x04, 0x01, 1, 0x04, 0x01, 2],
            Side::Client,
            0x04,
            "duplicate parameter",
        );
        // A varint followed by a stray byte.
        check(
            &[0x04, 0x02, 1, 2],
            Side::Client,
            0x04,
            "trailing bytes after the varint",
        );
        // disable_active_migration with a value.
        check(
            &[0x0c, 0x01, 0],
            Side::Client,
            0x0c,
            "disable_active_migration carries a value",
        );
        // An unknown GREASE id 27 is ignored.
        assert_eq!(
            TransportParameters::decode(&[27, 0x02, 0xde, 0xad], Side::Client),
            Ok(TransportParameters::default())
        );
    }

    proptest! {
        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..100)) {
            let _ = TransportParameters::decode(&bytes, Side::Server);
        }
    }
}
