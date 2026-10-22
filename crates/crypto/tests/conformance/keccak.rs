//! The Keccak team's known answers for Keccak-256, the hash Ethereum calls Keccak.
//!
//! These are the SHA-3 competition's round 3 files for Keccak[r = 1088, c = 512].
//! They use the original pad10*1 padding, without the SHA3 domain bits, as Ethereum does.
//!
//! Messages are given in bits, and the hasher takes whole bytes.
//! Lengths that are not a multiple of 8 are counted as unsupported.

use std::fs;

use axiom_crypto::keccak::Keccak256;

use crate::vectors::{Vectors, hex};

/// The fields of one file, in order, as key and value pairs.
fn fields(file: &str) -> Option<Vec<(String, String)>> {
    let path = Vectors::locate("keccak-kat")?.path(file);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    Some(
        text.lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split_once(" = "))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
    )
}

/// Runs a file of Len, Msg, MD triples and returns the byte-aligned and unsupported counts.
fn run_kat(file: &str) -> Option<(usize, usize)> {
    let fields = fields(file)?;
    let (mut run, mut unsupported) = (0, 0);
    for triple in fields.chunks(3) {
        let [(len, bits), (msg, message), (md, digest)] = triple else {
            panic!("{file}: truncated triple {triple:?}");
        };
        assert_eq!(
            (len.as_str(), msg.as_str(), md.as_str()),
            ("Len", "Msg", "MD")
        );
        let bits: usize = bits.parse().expect("bit length");
        if !bits.is_multiple_of(8) {
            unsupported += 1;
            continue;
        }
        // Len = 0 still writes one placeholder byte, so the message is cut to its length.
        let message = hex(message).expect("hex message");
        let message = &message[..bits / 8];
        assert_eq!(
            Keccak256::digest(message).to_vec(),
            hex(digest).expect("hex digest"),
            "{file}: Len = {bits}"
        );
        run += 1;
    }
    Some((run, unsupported))
}

#[test]
fn short_messages() {
    // Lengths 0 to 2047 bits: 256 whole-byte messages, up to 255 bytes.
    if let Some(counts) = run_kat("ShortMsgKAT_256.txt") {
        assert_eq!(counts, (256, 1792));
    }
}

#[test]
fn long_messages() {
    // Lengths 2048 to 34304 bits in steps of 64: 65 whole-byte messages, up to 4288 bytes.
    if let Some(counts) = run_kat("LongMsgKAT_256.txt") {
        assert_eq!(counts, (65, 448));
    }
}

#[test]
fn extremely_long_message() {
    let Some(fields) = fields("ExtremelyLongMsgKAT_256.txt") else {
        return;
    };
    // Fixture state: a 64-byte text repeated 16777216 times, 1 GiB in all.
    let [(_, repeat), (_, text), (_, digest)] = fields.as_slice() else {
        panic!("expected Repeat, Text, MD");
    };
    let repeat: usize = repeat.parse().expect("repeat count");
    assert_eq!((repeat, text.len()), (16_777_216, 64));

    // Absorb 4 MiB at a time: 65536 copies per update, 256 updates.
    let chunk = text.repeat(65_536);
    let mut hasher = Keccak256::new();
    for _ in 0..repeat / 65_536 {
        hasher.update(chunk.as_bytes());
    }
    assert_eq!(hasher.finalize().to_vec(), hex(digest).expect("hex digest"));
}
