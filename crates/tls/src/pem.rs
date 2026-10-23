//! PEM: base64 DER between BEGIN and END lines, the file form of certificates and keys.
//!
//! # Overview
//!
//! A file holds any number of blocks, with free text around them, per RFC 7468, section 2.
//!
//! ```text
//! -----BEGIN CERTIFICATE-----
//! MIIB...
//! -----END CERTIFICATE-----
//! ```
//!
//! The labels name the content:
//!
//! - CERTIFICATE;
//! - PRIVATE KEY for PKCS#8;
//! - EC PRIVATE KEY for SEC 1;
//! - RSA PRIVATE KEY for PKCS#1.
//!
//! Whitespace inside a block is ignored.
//! Headers, which only encrypted legacy keys carry, are refused.

use thiserror::Error;

/// The standard base64 alphabet of RFC 4648, section 4.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The prefix of an encapsulation boundary line.
const BEGIN: &str = "-----BEGIN ";

/// The prefix of the closing boundary line.
const END: &str = "-----END ";

/// The suffix of both boundary lines.
const DASHES: &str = "-----";

/// A PEM file that cannot be read.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PemError {
    /// The file is not text.
    #[error("PEM file is not UTF-8")]
    NotText,

    /// A block opens and never closes.
    #[error("block {label:?} has no END line")]
    Unterminated {
        /// The label of the open block.
        label: String,
    },

    /// A block closes with another label than it opened with.
    #[error("block opened as {begin:?} closes as {end:?}")]
    LabelMismatch {
        /// The opening label.
        begin: String,
        /// The closing label.
        end: String,
    },

    /// A block carries headers, as encrypted legacy keys do.
    #[error("block {label:?} carries headers; encrypted keys are not supported")]
    Headers {
        /// The label of the block.
        label: String,
    },

    /// A block body is not valid base64.
    #[error("block {label:?} is not valid base64")]
    InvalidBase64 {
        /// The label of the block.
        label: String,
    },
}

/// One decoded PEM block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PemBlock {
    /// The label between BEGIN and the dashes.
    pub label: String,
    /// The decoded content, DER for every label this stack reads.
    pub der: Vec<u8>,
}

impl PemBlock {
    /// Every block of a file, in order, skipping the text between blocks.
    ///
    /// # Errors
    ///
    /// Fails on a non-text file, an unterminated or mislabeled block, headers, or bad base64.
    pub fn parse_all(file: &[u8]) -> Result<Vec<Self>, PemError> {
        let text = str::from_utf8(file).map_err(|_| PemError::NotText)?;
        let mut blocks = Vec::new();
        let mut lines = text.lines().map(str::trim);
        while let Some(line) = lines.next() {
            let Some(label) = Self::boundary(line, BEGIN) else {
                continue;
            };
            let mut body = String::new();
            let mut closed = false;
            for line in lines.by_ref() {
                if let Some(end) = Self::boundary(line, END) {
                    if end != label {
                        return Err(PemError::LabelMismatch {
                            begin: label.to_owned(),
                            end: end.to_owned(),
                        });
                    }
                    closed = true;
                    break;
                }
                if line.contains(':') {
                    return Err(PemError::Headers {
                        label: label.to_owned(),
                    });
                }
                body.push_str(line);
            }
            if !closed {
                return Err(PemError::Unterminated {
                    label: label.to_owned(),
                });
            }
            let der = Self::decode_base64(&body).ok_or_else(|| PemError::InvalidBase64 {
                label: label.to_owned(),
            })?;
            blocks.push(Self {
                label: label.to_owned(),
                der,
            });
        }
        Ok(blocks)
    }

    /// The label of a boundary line with a given prefix.
    fn boundary<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
        line.strip_prefix(prefix)?.strip_suffix(DASHES)
    }

    /// Decodes padded standard base64, ignoring whitespace.
    ///
    /// Bits past the last byte must be zero, so each input has one spelling.
    fn decode_base64(text: &str) -> Option<Vec<u8>> {
        let symbols: Vec<u8> = text
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        if !symbols.len().is_multiple_of(4) {
            return None;
        }
        let padding = symbols
            .iter()
            .rev()
            .take_while(|&&byte| byte == b'=')
            .count();
        if padding > 2 {
            return None;
        }
        let data = &symbols[..symbols.len() - padding];
        let mut out = Vec::with_capacity(data.len() * 3 / 4);
        let mut accumulator = 0_u32;
        let mut bits = 0_u32;
        for &symbol in data {
            let value = ALPHABET.iter().position(|&known| known == symbol)?;
            accumulator = (accumulator << 6) | value as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((accumulator >> bits) as u8);
                accumulator &= (1 << bits) - 1;
            }
        }
        // The leftover bits must be zero.
        (accumulator == 0).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_with_text_between() {
        // RFC 4648, section 10: "foobar" is Zm9vYmFy, and "fo" is Zm8=.
        let file = b"comment\n-----BEGIN A-----\nZm9v\nYmFy\n-----END A-----\nmore\n-----BEGIN B-----\r\nZm8=\r\n-----END B-----\n";
        assert_eq!(
            PemBlock::parse_all(file),
            Ok(vec![
                PemBlock {
                    label: "A".to_owned(),
                    der: b"foobar".to_vec()
                },
                PemBlock {
                    label: "B".to_owned(),
                    der: b"fo".to_vec()
                },
            ])
        );
        assert_eq!(PemBlock::parse_all(b"no blocks here"), Ok(vec![]));
    }

    #[test]
    fn malformed_blocks() {
        let cases: [(&[u8], PemError); 5] = [
            (
                b"-----BEGIN A-----\nZm9v\n",
                PemError::Unterminated {
                    label: "A".to_owned(),
                },
            ),
            (
                b"-----BEGIN A-----\nZm9v\n-----END B-----\n",
                PemError::LabelMismatch {
                    begin: "A".to_owned(),
                    end: "B".to_owned(),
                },
            ),
            (
                b"-----BEGIN A-----\nProc-Type: 4,ENCRYPTED\nZm9v\n-----END A-----\n",
                PemError::Headers {
                    label: "A".to_owned(),
                },
            ),
            // Mutation: a symbol outside the alphabet, and nonzero bits after "fo".
            (
                b"-----BEGIN A-----\nZm9*\n-----END A-----\n",
                PemError::InvalidBase64 {
                    label: "A".to_owned(),
                },
            ),
            (
                b"-----BEGIN A-----\nZm9=\n-----END A-----\n",
                PemError::InvalidBase64 {
                    label: "A".to_owned(),
                },
            ),
        ];
        for (file, error) in cases {
            assert_eq!(PemBlock::parse_all(file), Err(error));
        }
    }
}
