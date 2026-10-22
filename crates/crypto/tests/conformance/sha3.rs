//! NIST CAVP known answers for SHA-3 and SHAKE, from the SHA3VS byte-oriented test files.
//!
//! # Overview
//!
//! Each hash runs three kinds of test, per the SHA-3 Validation System document.
//!
//! - Short and long messages: one digest per message.
//! - Monte Carlo: 100 checkpoints of a 1000-step chain, each step hashing the previous output.
//! - Variable output, SHAKE only: one output length per case.
//!
//! The byte-oriented files only list whole-byte messages, so every case runs.

use std::fs;

use axiom_crypto::keccak::{Sha3, Shake};

use crate::vectors::{Vectors, hex};

/// The key and value pairs of one response file, in order, without comments or brackets.
fn fields(file: &str) -> Option<Vec<(String, String)>> {
    let path = Vectors::locate("nist-sha3")?.path(file);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    Some(
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && !line.starts_with('['))
            .filter_map(|line| line.split_once(" = "))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
    )
}

/// The value of a bracketed parameter, such as the maximum output length.
fn bracket(file: &str, name: &str) -> Option<usize> {
    let path = Vectors::locate("nist-sha3")?.path(file);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    text.lines()
        .filter_map(|line| line.trim().strip_prefix('[')?.strip_suffix(']'))
        .filter_map(|inner| inner.split_once(" = "))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.parse().expect("integer parameter"))
}

/// Decodes a message of a bit length, which a zero length writes as one placeholder byte.
fn message(bits: &str, text: &str) -> Vec<u8> {
    let bits: usize = bits.parse().expect("bit length");
    assert!(bits.is_multiple_of(8), "byte-oriented files only");
    let bytes = hex(text).expect("hex message");
    bytes[..bits / 8].to_vec()
}

/// Runs a file of Len, Msg, MD triples and returns how many ran.
fn run_sha3_messages<const RATE: usize, const DIGEST: usize>(file: &str) -> Option<usize> {
    let fields = fields(file)?;
    let mut run = 0;
    for triple in fields.chunks(3) {
        let [(len, bits), (_, text), (md, digest)] = triple else {
            panic!("{file}: truncated triple {triple:?}");
        };
        assert_eq!((len.as_str(), md.as_str()), ("Len", "MD"));
        assert_eq!(
            Sha3::<RATE, DIGEST>::digest(&message(bits, text)).to_vec(),
            hex(digest).expect("hex digest"),
            "{file}: Len = {bits}"
        );
        run += 1;
    }
    Some(run)
}

/// Runs the SHA-3 Monte Carlo chain and returns how many checkpoints matched.
fn run_sha3_monte<const RATE: usize, const DIGEST: usize>(file: &str) -> Option<usize> {
    let fields = fields(file)?;
    let (seed, checkpoints) = fields.split_first().expect("a seed");
    assert_eq!(seed.0, "Seed");

    // SHA3VS, section 6.2.3: MD_i = SHA3(MD_(i-1)) for 1000 steps per checkpoint.
    let mut digest = hex(&seed.1).expect("hex seed");
    let mut run = 0;
    for pair in checkpoints.chunks(2) {
        let [(count, _), (md, expected)] = pair else {
            panic!("{file}: truncated checkpoint");
        };
        assert_eq!((count.as_str(), md.as_str()), ("COUNT", "MD"));
        for _ in 0..1000 {
            digest = Sha3::<RATE, DIGEST>::digest(&digest).to_vec();
        }
        assert_eq!(
            digest,
            hex(expected).expect("hex digest"),
            "{file}: checkpoint {run}"
        );
        run += 1;
    }
    Some(run)
}

/// The first bytes of a SHAKE output stream.
fn shake<const RATE: usize>(data: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    Shake::<RATE>::digest_into(data, &mut out);
    out
}

/// Runs a file of Len, Msg, Output triples at the file's fixed output length.
fn run_shake_messages<const RATE: usize>(file: &str) -> Option<usize> {
    let fields = fields(file)?;
    let mut run = 0;
    for triple in fields.chunks(3) {
        let [(len, bits), (_, text), (output, expected)] = triple else {
            panic!("{file}: truncated triple {triple:?}");
        };
        assert_eq!((len.as_str(), output.as_str()), ("Len", "Output"));
        let expected = hex(expected).expect("hex output");
        assert_eq!(
            shake::<RATE>(&message(bits, text), expected.len()),
            expected,
            "{file}: Len = {bits}"
        );
        run += 1;
    }
    Some(run)
}

/// Runs a file of COUNT, Outputlen, Msg, Output cases and returns how many ran.
fn run_shake_variable<const RATE: usize>(file: &str) -> Option<usize> {
    let fields = fields(file)?;
    let mut run = 0;
    for case in fields.chunks(4) {
        let [_, (_, bits), (_, text), (_, expected)] = case else {
            panic!("{file}: truncated case {case:?}");
        };
        let bits: usize = bits.parse().expect("output length");
        let expected = hex(expected).expect("hex output");
        assert_eq!(expected.len(), bits / 8);
        assert_eq!(
            shake::<RATE>(&hex(text).expect("hex message"), bits / 8),
            expected,
            "{file}: case {run}"
        );
        run += 1;
    }
    Some(run)
}

/// Runs the SHAKE Monte Carlo chain, whose output length follows the previous output.
fn run_shake_monte<const RATE: usize>(file: &str) -> Option<usize> {
    let fields = fields(file)?;
    let min = bracket(file, "Minimum Output Length (bits)")? / 8;
    let max = bracket(file, "Maximum Output Length (bits)")? / 8;
    let (seed, checkpoints) = fields.split_first().expect("a seed");
    assert_eq!(seed.0, "Msg");

    // SHA3VS, section 6.3.3:
    //
    //     Msg_i       = leftmost 128 bits of Output_(i-1), zero-padded when shorter
    //     Output_i    = SHAKE(Msg_i, Outputlen)
    //     Outputlen   = min + (rightmost 16 bits of Output_i) mod (max - min + 1)
    let mut output = hex(&seed.1).expect("hex seed");
    let mut length = max;
    let mut run = 0;
    for case in checkpoints.chunks(3) {
        let [_, (_, bits), (_, expected)] = case else {
            panic!("{file}: truncated checkpoint");
        };
        for _ in 0..1000 {
            let mut message = [0; 16];
            let take = output.len().min(16);
            message[..take].copy_from_slice(&output[..take]);
            output = shake::<RATE>(&message, length);
            let tail = u16::from_be_bytes([output[output.len() - 2], output[output.len() - 1]]);
            length = min + usize::from(tail) % (max - min + 1);
        }
        assert_eq!(output.len() * 8, bits.parse::<usize>().expect("length"));
        assert_eq!(
            output,
            hex(expected).expect("hex output"),
            "{file}: checkpoint {run}"
        );
        run += 1;
    }
    Some(run)
}

#[test]
fn sha3_short_messages() {
    // Lengths 0 to one rate in bytes, one case per byte length.
    let counts = [
        run_sha3_messages::<144, 28>("SHA3_224ShortMsg.rsp"),
        run_sha3_messages::<136, 32>("SHA3_256ShortMsg.rsp"),
        run_sha3_messages::<104, 48>("SHA3_384ShortMsg.rsp"),
        run_sha3_messages::<72, 64>("SHA3_512ShortMsg.rsp"),
    ];
    if counts.iter().all(Option::is_some) {
        assert_eq!(counts, [Some(145), Some(137), Some(105), Some(73)]);
    }
}

#[test]
fn sha3_long_messages() {
    // 100 messages per digest length, each several blocks long.
    let counts = [
        run_sha3_messages::<144, 28>("SHA3_224LongMsg.rsp"),
        run_sha3_messages::<136, 32>("SHA3_256LongMsg.rsp"),
        run_sha3_messages::<104, 48>("SHA3_384LongMsg.rsp"),
        run_sha3_messages::<72, 64>("SHA3_512LongMsg.rsp"),
    ];
    if counts.iter().all(Option::is_some) {
        assert_eq!(counts, [Some(100); 4]);
    }
}

#[test]
fn sha3_monte_carlo() {
    // 100 checkpoints of 1000 chained digests per digest length.
    let counts = [
        run_sha3_monte::<144, 28>("SHA3_224Monte.rsp"),
        run_sha3_monte::<136, 32>("SHA3_256Monte.rsp"),
        run_sha3_monte::<104, 48>("SHA3_384Monte.rsp"),
        run_sha3_monte::<72, 64>("SHA3_512Monte.rsp"),
    ];
    if counts.iter().all(Option::is_some) {
        assert_eq!(counts, [Some(100); 4]);
    }
}

#[test]
fn shake_short_and_long_messages() {
    let counts = [
        run_shake_messages::<168>("SHAKE128ShortMsg.rsp"),
        run_shake_messages::<136>("SHAKE256ShortMsg.rsp"),
        run_shake_messages::<168>("SHAKE128LongMsg.rsp"),
        run_shake_messages::<136>("SHAKE256LongMsg.rsp"),
    ];
    if counts.iter().all(Option::is_some) {
        assert_eq!(counts, [Some(337), Some(273), Some(100), Some(100)]);
    }
}

#[test]
fn shake_variable_output() {
    // Output lengths from 16 bytes to 140 bytes, across block boundaries.
    let counts = [
        run_shake_variable::<168>("SHAKE128VariableOut.rsp"),
        run_shake_variable::<136>("SHAKE256VariableOut.rsp"),
    ];
    if counts.iter().all(Option::is_some) {
        assert_eq!(counts, [Some(1126), Some(1246)]);
    }
}

#[test]
fn shake_monte_carlo() {
    let counts = [
        run_shake_monte::<168>("SHAKE128Monte.rsp"),
        run_shake_monte::<136>("SHAKE256Monte.rsp"),
    ];
    if counts.iter().all(Option::is_some) {
        assert_eq!(counts, [Some(100); 2]);
    }
}
