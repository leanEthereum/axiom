//! NIST CAVP known answers for AES-128 and AES-128-GCM.
//!
//! # Overview
//!
//! The AES files are the AESAVS known-answer tests: GFSbox, KeySbox, VarKey, and VarTxt.
//! Their DECRYPT halves list the same key, plaintext, and ciphertext triples in reverse.
//! The crate only runs the cipher forward, as CTR and GCM need, so both halves check encryption.
//!
//! The GCM files are the GCMVS tests with a 128-bit key.
//! The crate takes 96-bit nonces only, and opens only full 128-bit tags.
//! Encryption cases with a shorter tag compare its prefix, per SP 800-38D, section 5.2.1.2.
//! Every other parameter set is counted as unsupported.

use std::fs;

use axiom_crypto::aes::{Aes128, Aes128Gcm};

use crate::vectors::{Vectors, hex};

/// One record of a response file, with the bracketed parameters in force above it.
#[derive(Clone, Debug, Default)]
struct Record {
    /// Bracketed parameters, such as IVlen, in file order.
    parameters: Vec<(String, String)>,
    /// The record's fields, such as Key, in file order.
    fields: Vec<(String, String)>,
    /// Whether the record ends with FAIL, marking an input that must not authenticate.
    fail: bool,
}

impl Record {
    /// A field's text.
    fn text(&self, name: &str) -> &str {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map_or_else(|| panic!("missing field {name}"), |(_, value)| value)
    }

    /// A field's hex, decoded.
    fn bytes(&self, name: &str) -> Vec<u8> {
        hex(self.text(name)).unwrap_or_else(|| panic!("bad hex in {name}"))
    }

    /// A bracketed parameter's integer value.
    fn parameter(&self, name: &str) -> u64 {
        self.parameters
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| value.parse().ok())
            .unwrap_or_else(|| panic!("missing parameter {name}"))
    }
}

/// The records of one response file.
#[derive(Debug)]
struct ResponseFile {
    /// Every record, in file order.
    records: Vec<Record>,
}

impl ResponseFile {
    /// Loads a file of the CAVP set, or none when the vectors are absent.
    fn load(file: &str) -> Option<Self> {
        let path = Vectors::locate("nist-cavp")?.path(file);
        let text =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        Some(Self::parse(&text))
    }

    /// Parses the line format: comments, bracketed parameters, and key = value records.
    fn parse(text: &str) -> Self {
        let mut records: Vec<Record> = Vec::new();
        let mut parameters: Vec<(String, String)> = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(inner) = line
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            {
                // A bracket either sets a parameter or names a section such as ENCRYPT.
                let (key, value) = inner.split_once('=').unwrap_or((inner, ""));
                parameters.retain(|(name, _)| name != key.trim());
                parameters.push((key.trim().to_owned(), value.trim().to_owned()));
                continue;
            }
            if line == "FAIL" {
                records.last_mut().expect("FAIL follows a record").fail = true;
                continue;
            }
            let (key, value) = line.split_once('=').expect("key = value line");
            let (key, value) = (key.trim().to_owned(), value.trim().to_owned());
            // A count opens a new record.
            if key.eq_ignore_ascii_case("count") {
                records.push(Record {
                    parameters: parameters.clone(),
                    ..Record::default()
                });
            }
            records
                .last_mut()
                .expect("fields follow a count")
                .fields
                .push((key, value));
        }
        Self { records }
    }
}

#[test]
fn aes_128_known_answers() {
    // Fixture state: 7 + 21 + 128 + 128 triples, each listed once to encrypt and once to decrypt.
    let files = [
        ("aes/ECBGFSbox128.rsp", 14),
        ("aes/ECBKeySbox128.rsp", 42),
        ("aes/ECBVarKey128.rsp", 256),
        ("aes/ECBVarTxt128.rsp", 256),
    ];
    for (name, expected) in files {
        let Some(file) = ResponseFile::load(name) else {
            return;
        };
        for record in &file.records {
            let key: [u8; 16] = record.bytes("KEY").try_into().expect("128-bit key");
            let mut block: [u8; 16] = record.bytes("PLAINTEXT").try_into().expect("one block");
            Aes128::new(&key).encrypt_block(&mut block);
            assert_eq!(
                block[..],
                record.bytes("CIPHERTEXT")[..],
                "{name} count {}",
                record.text("COUNT")
            );
        }
        assert_eq!(file.records.len(), expected, "{name}");
    }
}

#[test]
fn aes_128_gcm_encrypt() {
    let Some(file) = ResponseFile::load("gcm/gcmEncryptExtIV128.rsp") else {
        return;
    };
    let mut unsupported = 0;
    let mut run = 0;
    for record in &file.records {
        let Ok(nonce) = <[u8; 12]>::try_from(record.bytes("IV").as_slice()) else {
            unsupported += 1;
            continue;
        };
        let key: [u8; 16] = record.bytes("Key").try_into().expect("128-bit key");
        let sealed = Aes128Gcm::new(&key).seal(&nonce, &record.bytes("AAD"), &record.bytes("PT"));

        // The sealed bytes are the ciphertext, then the full tag; a short tag is its prefix.
        let ciphertext = record.bytes("CT");
        let tag = record.bytes("Tag");
        assert_eq!(record.parameter("Taglen"), tag.len() as u64 * 8);
        let (sealed_ciphertext, full_tag) = sealed.split_at(ciphertext.len());
        assert_eq!(
            sealed_ciphertext,
            ciphertext,
            "count {}",
            record.text("Count")
        );
        assert_eq!(
            &full_tag[..tag.len()],
            tag,
            "count {}",
            record.text("Count")
        );
        run += 1;
    }
    // 7875 cases: 2625 with a 96-bit nonce, over 7 tag lengths, and 5250 with 8 or 1024 bits.
    assert_eq!((run, unsupported), (2625, 5250));
}

#[test]
fn aes_128_gcm_decrypt() {
    let Some(file) = ResponseFile::load("gcm/gcmDecrypt128.rsp") else {
        return;
    };
    let (mut opened, mut refused, mut unsupported) = (0, 0, 0);
    for record in &file.records {
        let nonce = <[u8; 12]>::try_from(record.bytes("IV").as_slice());
        let tag = <[u8; 16]>::try_from(record.bytes("Tag").as_slice());
        let (Ok(nonce), Ok(tag)) = (nonce, tag) else {
            unsupported += 1;
            continue;
        };
        let key: [u8; 16] = record.bytes("Key").try_into().expect("128-bit key");
        let sealed = [record.bytes("CT"), tag.to_vec()].concat();
        let result = Aes128Gcm::new(&key).open(&nonce, &record.bytes("AAD"), &sealed);

        // A FAIL record must not authenticate; any other must open to its plaintext.
        if record.fail {
            assert!(result.is_err(), "count {} opened", record.text("Count"));
            refused += 1;
        } else {
            assert_eq!(
                result,
                Ok(record.bytes("PT")),
                "count {}",
                record.text("Count")
            );
            opened += 1;
        }
    }
    // 7875 cases: 375 with a 96-bit nonce and a full tag, the rest unsupported.
    assert_eq!((opened + refused, unsupported), (375, 7500));
    assert!(
        opened > 0 && refused > 0,
        "{opened} opened, {refused} refused"
    );
}
