//! The HTTP/1.1 wire format, free of any input or output.
//!
//! Everything here works on byte slices, so tests drive it directly.

mod body;
mod encode;
mod head;

pub use body::{BodyLength, ChunkedDecoder};
pub(crate) use encode::Encoder;
pub use head::{RequestHead, ResponseHead};

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::Limits;

    proptest! {
        #[test]
        fn noise_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            // Any outcome is fine; none may panic, and consumed counts stay in range.
            let limits = Limits { max_head_bytes: 256, max_headers: 8, max_body_bytes: 256 };
            if let Ok(Some((_, used))) = RequestHead::parse(&bytes, &limits) {
                prop_assert!(used <= bytes.len());
            }
            if let Ok(Some((_, used))) = ResponseHead::parse(&bytes, &limits) {
                prop_assert!(used <= bytes.len());
            }
            let mut decoder = ChunkedDecoder::new(256);
            if let Ok(used) = decoder.decode(&bytes, &mut Vec::new()) {
                prop_assert!(used <= bytes.len());
            }
        }

        #[test]
        fn http_alphabet_never_panics(text in "[A-Z /0-9a-f:\r\n;.-]{0,200}") {
            // Text built from the protocol's own alphabet reaches deeper than noise.
            let limits = Limits::DEFAULT;
            let _ = RequestHead::parse(text.as_bytes(), &limits);
            let _ = ResponseHead::parse(text.as_bytes(), &limits);
            let _ = ChunkedDecoder::new(1024).decode(text.as_bytes(), &mut Vec::new());
        }
    }
}
