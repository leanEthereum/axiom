//! The expand_message_xmd expander of RFC 9380 section 5.3.1, instantiated with SHA-256.
//!
//! It stretches a message into any number of uniform bytes, bound to a domain separation tag.
//! Each output block hashes the XOR of the first block with the previous one, chaining all of them to b_0.
//!
//! ```text
//!     b_0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST')
//!     b_1 = H(b_0 || 0x01 || DST')
//!     b_i = H((b_0 xor b_{i-1}) || i || DST')
//!     DST' = DST || len(DST)
//! ```

use sha2::{Digest, Sha256};

/// Output size of SHA-256 in bytes, b_in_bytes in the RFC.
const HASH_BYTES: usize = 32;

/// Input block size of SHA-256 in bytes, s_in_bytes in the RFC, the length of Z_pad.
const BLOCK_BYTES: usize = 64;

/// Prefix that hashes an oversized tag down to 32 bytes, RFC 9380 section 5.3.3.
const OVERSIZE_DST_PREFIX: &[u8] = b"H2C-OVERSIZE-DST-";

/// Fills the output with uniform bytes derived from the message and the domain separation tag.
///
/// # Panics
///
/// Panics when the output exceeds 255 hash blocks (8160 bytes), the RFC's limit.
/// Callers in this crate request 256 bytes.
pub(crate) fn expand_message_xmd(message: &[u8], dst: &[u8], out: &mut [u8]) {
    // Tags longer than 255 bytes do not fit their one-byte length, so they are hashed first.
    let hashed_dst;
    let dst = if dst.len() > 255 {
        hashed_dst = Sha256::new()
            .chain_update(OVERSIZE_DST_PREFIX)
            .chain_update(dst)
            .finalize();
        hashed_dst.as_slice()
    } else {
        dst
    };
    // Both lengths fit: the tag is at most 255 bytes, the output at most 255 * 32 < 2^16.
    let dst_length = [u8::try_from(dst.len()).unwrap_or(u8::MAX)];
    let blocks = out.len().div_ceil(HASH_BYTES);
    assert!(
        blocks <= 255,
        "expand_message_xmd output is limited to 255 hash blocks"
    );
    let output_length = u16::try_from(out.len()).unwrap_or(u16::MAX).to_be_bytes();

    // b_0 commits to the message, the output length, and the tag.
    let b_0 = Sha256::new()
        .chain_update([0_u8; BLOCK_BYTES])
        .chain_update(message)
        .chain_update(output_length)
        .chain_update([0_u8])
        .chain_update(dst)
        .chain_update(dst_length)
        .finalize();

    // b_1 starts the chain; each later block mixes b_0 back in.
    let mut previous = [0_u8; HASH_BYTES];
    for (index, chunk) in (1_u8..).zip(out.chunks_mut(HASH_BYTES)) {
        // The first block has previous = 0, so b_0 xor previous = b_0 as the RFC writes it.
        let mut mixed = [0_u8; HASH_BYTES];
        for ((mixed, b0), prev) in mixed.iter_mut().zip(b_0).zip(previous) {
            *mixed = b0 ^ prev;
        }
        let block = Sha256::new()
            .chain_update(mixed)
            .chain_update([index])
            .chain_update(dst)
            .chain_update(dst_length)
            .finalize();
        previous.copy_from_slice(&block);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The messages of RFC 9380 appendix K, by index.
    fn rfc_message(index: usize) -> Vec<u8> {
        match index {
            0 => Vec::new(),
            1 => b"abc".to_vec(),
            2 => b"abcdef0123456789".to_vec(),
            3 => [b"q128_".as_slice(), &[b'q'; 128]].concat(),
            _ => [b"a512_".as_slice(), &[b'a'; 512]].concat(),
        }
    }

    /// Decodes a hex string.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc_9380_appendix_k1_vectors() {
        // Fixture state: five messages, each expanded to 32 and to 128 bytes.
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let expected_32 = [
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
            "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
            "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9",
            "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c",
        ];
        let expected_128 = [
            concat!(
                "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe",
                "e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18",
                "eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc",
                "c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
            ),
            concat!(
                "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a",
                "647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635",
                "bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00",
                "058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
            ),
            concat!(
                "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9",
                "ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4b",
                "c95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be1",
                "4cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df",
            ),
            concat!(
                "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bb",
                "d88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0",
                "e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b",
                "29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a",
            ),
            concat!(
                "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d0",
                "6d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608",
                "ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4",
                "a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487",
            ),
        ];

        for (index, (short, long)) in expected_32.iter().zip(expected_128).enumerate() {
            let message = rfc_message(index);
            let mut out = [0_u8; 32];
            expand_message_xmd(&message, dst, &mut out);
            assert_eq!(out.to_vec(), hex(short), "32-byte case {index}");

            let mut out = [0_u8; 128];
            expand_message_xmd(&message, dst, &mut out);
            assert_eq!(out.to_vec(), hex(long), "128-byte case {index}");
        }
    }

    #[test]
    fn oversized_tag_is_replaced_by_its_hash() {
        // A 256-byte tag must behave exactly like its 32-byte digest under the oversize prefix.
        let long_dst = [7_u8; 256];
        let digest = Sha256::new()
            .chain_update(OVERSIZE_DST_PREFIX)
            .chain_update(long_dst)
            .finalize();

        let mut with_long = [0_u8; 64];
        let mut with_digest = [0_u8; 64];
        expand_message_xmd(b"msg", &long_dst, &mut with_long);
        expand_message_xmd(b"msg", &digest, &mut with_digest);
        assert_eq!(with_long, with_digest);
    }
}
