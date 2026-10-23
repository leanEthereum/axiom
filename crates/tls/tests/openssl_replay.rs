//! Sessions with an OpenSSL 3.5 server, recorded once and replayed byte for byte.
//!
//! Each fixture holds one session of the client against `openssl s_server -www`:
//!
//! - lines starting with C: what the client sent, in order;
//! - lines starting with S: what the server sent, in the chunks the socket delivered;
//! - the line starting with P: the decrypted page the server answered.
//!
//! The client's randomness and clock are fixed, so a replay must send exactly the recorded bytes.
//! Every server byte then authenticates only if the client derived the same keys OpenSSL did.
//! The server certificates come from the HTTP crate's test PKI, under its P-384 root.

use std::{fmt::Write, fs, path::PathBuf, sync::Arc};

use axiom_tls::{
    ClientConfig, Connection, ProtocolError, Randomness, TlsError,
    pki::{RootStore, WebPkiVerifier},
};

/// The instant the sessions ran at, in 2027, inside every certificate's window.
const NOW: u64 = 1_800_000_000;

/// A fixture file's path.
fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

/// Decodes hex.
fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The client as it ran: fixed randomness, the test root, and the request queued at once.
fn client() -> Connection<WebPkiVerifier> {
    let mut roots = RootStore::new();
    let root = fs::read(fixture("../http/tests/fixtures/root.pem")).expect("root");
    roots.add_pem_bundle(&root).expect("PEM");
    let verifier = WebPkiVerifier::new(Arc::new(roots), "localhost".parse().expect("name"));
    let mut connection = Connection::client(
        ClientConfig::https(Some("localhost".to_owned())),
        verifier,
        Randomness::from_seed([7; 32]),
        NOW,
    );
    connection
        .write_plaintext(b"GET / HTTP/1.0\r\n\r\n")
        .expect("queued");
    connection
}

/// Replays one session, returning the page, and checks every client byte against the record.
///
/// A mutation, if given, flips one bit of the server's chunk at that index, at that byte.
fn replay(name: &str, mutation: Option<(usize, usize)>) -> Result<Vec<u8>, TlsError> {
    let log = fs::read_to_string(fixture(&format!("tests/fixtures/openssl-{name}.txt")))
        .expect("fixture");
    let mut connection = client();
    let mut page = Vec::new();
    let mut server_chunk = 0;
    for line in log.lines() {
        let (kind, bytes) = line.split_at(2);
        match kind {
            "C " => assert_eq!(hex_text(&connection.take_tls()), bytes, "{name}"),
            "S " => {
                let mut bytes = hex(bytes);
                if let Some((chunk, at)) = mutation
                    && chunk == server_chunk
                {
                    bytes[at] ^= 1;
                }
                server_chunk += 1;
                connection.read_tls(&bytes)?;
                let mut buffer = [0; 4096];
                loop {
                    let read = connection.read_plaintext(&mut buffer);
                    if read == 0 {
                        break;
                    }
                    page.extend_from_slice(&buffer[..read]);
                }
            }
            "P " => {
                assert_eq!(page, hex(bytes), "{name}: page");
                assert!(connection.peer_closed(), "{name}: close_notify");
            }
            other => panic!("unknown line kind {other:?}"),
        }
    }
    Ok(page)
}

/// Hex of bytes, so client output compares as text in failure messages.
fn hex_text(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        // Writing to a string cannot fail.
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[test]
fn sessions_replay_byte_for_byte() {
    // Each tuple: fixture, then the protocol and cipher OpenSSL reports in its page.
    let cases = [
        (
            "tls12-ecdsa-aes-gcm",
            "New, TLSv1.2, Cipher is ECDHE-ECDSA-AES128-GCM-SHA256",
        ),
        (
            "tls12-rsa-chacha-p256",
            "New, TLSv1.2, Cipher is ECDHE-RSA-CHACHA20-POLY1305",
        ),
        (
            "tls13-rsa-chacha",
            "New, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256",
        ),
    ];
    for (name, line) in cases {
        let page = String::from_utf8(replay(name, None).expect(name)).expect("text page");
        assert!(page.starts_with("HTTP/1.0 200 ok"), "{name}");
        assert!(page.contains(line), "{name}: {line}");
    }
}

/// The server chunks of a fixture, decoded.
fn server_chunks(name: &str) -> Vec<Vec<u8>> {
    fs::read_to_string(fixture(&format!("tests/fixtures/openssl-{name}.txt")))
        .expect("fixture")
        .lines()
        .filter_map(|line| line.strip_prefix("S "))
        .map(hex)
        .collect()
}

/// The offset of the last byte of the first plaintext handshake message of a type in a chunk.
fn message_end(chunk: &[u8], kind: u8) -> usize {
    let mut record = 0;
    // Records: type, version, length; each holds whole handshake messages here.
    while record < chunk.len() {
        let length = usize::from(u16::from_be_bytes([chunk[record + 3], chunk[record + 4]]));
        let mut at = record + 5;
        while chunk[record] == 22 && at < record + 5 + length {
            let body = usize::from(chunk[at + 1]) << 16
                | usize::from(chunk[at + 2]) << 8
                | usize::from(chunk[at + 3]);
            if chunk[at] == kind {
                return at + 3 + body;
            }
            at += 4 + body;
        }
        record += 5 + length;
    }
    panic!("no message of type {kind}");
}

#[test]
fn a_flipped_server_bit_is_refused() {
    // Mutation: the last byte of the TLS 1.2 ServerKeyExchange, inside its ECDSA signature.
    let at = message_end(&server_chunks("tls12-ecdsa-aes-gcm")[0], 12);
    assert_eq!(
        replay("tls12-ecdsa-aes-gcm", Some((0, at))),
        Err(TlsError::Protocol(
            ProtocolError::InvalidKeyExchangeSignature
        ))
    );

    // Mutation: the last byte of the TLS 1.2 server Finished record, its tag.
    let finished = server_chunks("tls12-rsa-chacha-p256")[1].len() - 1;
    assert_eq!(
        replay("tls12-rsa-chacha-p256", Some((1, finished))),
        Err(TlsError::Protocol(ProtocolError::BadRecordMac))
    );

    // Mutation: the last byte of the TLS 1.3 server flight, the tag of its encrypted record.
    let flight = server_chunks("tls13-rsa-chacha")[0].len() - 1;
    assert_eq!(
        replay("tls13-rsa-chacha", Some((0, flight))),
        Err(TlsError::Protocol(ProtocolError::BadRecordMac))
    );
}
