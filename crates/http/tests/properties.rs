//! Laws of the pure wire format, checked on random messages and random noise.

use axiom_http::{
    BodyLength, ChunkedDecoder, Limits, Method, ProtocolError, Request, RequestHead, Response,
    ResponseHead, StatusCode,
};
use proptest::prelude::*;

/// Any supported method.
fn method() -> impl Strategy<Value = Method> {
    prop_oneof![
        Just(Method::Get),
        Just(Method::Head),
        Just(Method::Post),
        Just(Method::Put),
        Just(Method::Delete),
        Just(Method::Options),
        Just(Method::Patch),
    ]
}

/// Header fields with token names and values free of control bytes.
fn fields() -> impl Strategy<Value = Vec<(String, String)>> {
    proptest::collection::vec(("x-[a-z0-9-]{1,12}", "[!-~]([ !-~]{0,20}[!-~])?"), 0..8)
}

/// Encodes a body with the chunked coding, cutting it at the given sizes.
///
/// ```text
///     body "hello", sizes [2, 9]  ->  "2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n"
/// ```
fn chunked(body: &[u8], sizes: &[usize]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    let mut sizes = sizes.iter().cycle();
    while !rest.is_empty() {
        // Sizes cycle; zero would end the body early, so it becomes one.
        let size = sizes.next().copied().unwrap_or(1).clamp(1, rest.len());
        out.extend_from_slice(format!("{size:x}\r\n").as_bytes());
        out.extend_from_slice(&rest[..size]);
        out.extend_from_slice(b"\r\n");
        rest = &rest[size..];
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

proptest! {
    #[test]
    fn request_encode_then_parse(
        method in method(),
        path in "/[a-z0-9/_.-]{0,30}",
        query in proptest::option::of("[a-z0-9=&]{0,20}"),
        fields in fields(),
        body in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        // Build the request the way a caller would.
        let target = match &query {
            Some(query) => format!("{path}?{query}"),
            None => path,
        };
        let mut request = Request::new(method, &target);
        for (name, value) in &fields {
            request.headers.append(name, value.as_str());
        }
        request.body = body.clone();

        // Encode, then parse the head back from the bytes.
        let bytes = request.encode("host:1").unwrap();
        let (head, used) = RequestHead::parse(&bytes, &Limits::DEFAULT).unwrap().unwrap();
        prop_assert_eq!(head.method, method);
        prop_assert_eq!(&head.target, &target);
        for (name, value) in &fields {
            prop_assert!(head.headers.get_all(name).any(|v| v == value));
        }

        // The declared length frames exactly the body that was sent.
        let expected = match head.body_length().unwrap() {
            BodyLength::Fixed(length) => length as usize,
            BodyLength::Empty => 0,
            other => panic!("unexpected framing {other:?}"),
        };
        prop_assert_eq!(&bytes[used..], &body[..]);
        prop_assert_eq!(expected, body.len());
    }

    #[test]
    fn response_encode_then_parse(
        code in 200_u16..600,
        fields in fields(),
        body in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let status = StatusCode::new(code).unwrap();
        let mut response = Response::new(status);
        for (name, value) in &fields {
            response.headers.append(name, value.as_str());
        }
        response.body = body.clone();

        // Parse the head back and frame the body from its declared length.
        let bytes = response.encode(false).unwrap();
        let (head, used) = ResponseHead::parse(&bytes, &Limits::DEFAULT).unwrap().unwrap();
        prop_assert_eq!(head.status, status);
        match head.body_length(Method::Get).unwrap() {
            BodyLength::Fixed(length) => {
                prop_assert_eq!(length as usize, body.len());
                prop_assert_eq!(&bytes[used..], &body[..]);
            }
            // 204 and 304 carry nothing.
            BodyLength::Empty => prop_assert_eq!(used, bytes.len()),
            other => panic!("unexpected framing {other:?}"),
        }
    }

    #[test]
    fn chunked_decode_any_split(
        body in proptest::collection::vec(any::<u8>(), 0..2000),
        sizes in proptest::collection::vec(1_usize..300, 1..10),
        cuts in proptest::collection::vec(1_usize..64, 1..20),
        next in proptest::collection::vec(any::<u8>(), 0..20),
    ) {
        // A chunked body followed by the start of another message.
        let mut stream = chunked(&body, &sizes);
        let end = stream.len();
        stream.extend_from_slice(&next);

        // Feed it in pieces of arbitrary sizes, as socket reads would arrive.
        let mut decoder = ChunkedDecoder::new(body.len());
        let mut decoded = Vec::new();
        let mut at = 0;
        let mut cuts = cuts.iter().cycle();
        while !decoder.is_done() && at < stream.len() {
            let piece = (*cuts.next().unwrap()).min(stream.len() - at);
            let used = decoder.decode(&stream[at..at + piece], &mut decoded).unwrap();
            at += used;
            // The decoder consumes the whole piece unless the body ended inside it.
            if used < piece {
                prop_assert!(decoder.is_done());
            }
        }

        // The whole body comes back, and the next message's bytes are untouched.
        prop_assert!(decoder.is_done());
        prop_assert_eq!(decoded, body);
        prop_assert_eq!(at, end);
    }

    #[test]
    fn chunked_bound_is_exact(body in proptest::collection::vec(any::<u8>(), 1..500)) {
        // A bound one byte short of the body rejects it.
        let stream = chunked(&body, &[7]);
        let mut decoder = ChunkedDecoder::new(body.len() - 1);
        prop_assert_eq!(
            decoder.decode(&stream, &mut Vec::new()),
            Err(ProtocolError::BodyTooLarge)
        );
    }

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
