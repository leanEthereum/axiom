//! A strict DER reader for the few structures the vector files wrap their inputs in.
//!
//! The crate takes raw integers and points, so the containers are unwrapped here.
//! The reader accepts minimal DER only, per ITU-T X.690, section 10.
//! Encoding defects in signatures are therefore caught by this reader, not by the crate.

/// A cursor over DER bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DerReader<'a> {
    /// The bytes not yet read.
    rest: &'a [u8],
}

impl<'a> DerReader<'a> {
    /// A reader over the given bytes.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Holds when every byte has been read.
    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Reads one element of the given tag and returns its content.
    ///
    /// Lengths below 128 must use the short form.
    /// Longer ones use the long form with the fewest bytes and no leading zero, at most two bytes.
    pub(crate) fn element(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (&found, rest) = self.rest.split_first()?;
        let (&first, mut rest) = rest.split_first()?;
        if found != tag {
            return None;
        }
        let length = match first {
            0x00..=0x7f => usize::from(first),
            0x81 => {
                let (&byte, tail) = rest.split_first()?;
                rest = tail;
                // A long form for a length below 128 is not minimal.
                (byte >= 0x80).then_some(usize::from(byte))?
            }
            0x82 => {
                let (bytes, tail) = rest.split_first_chunk::<2>()?;
                rest = tail;
                // A leading zero byte would fit the one-byte long form.
                (bytes[0] != 0).then_some(usize::from(u16::from_be_bytes(*bytes)))?
            }
            _ => return None,
        };
        if rest.len() < length {
            return None;
        }
        let (content, rest) = rest.split_at(length);
        self.rest = rest;
        Some(content)
    }

    /// Reads a SEQUENCE and returns a reader over its content.
    pub(crate) fn sequence(&mut self) -> Option<Self> {
        self.element(0x30).map(Self::new)
    }

    /// Reads a non-negative INTEGER in minimal form and returns its magnitude.
    ///
    /// The magnitude keeps no sign byte; zero comes back as a single zero byte.
    pub(crate) fn integer(&mut self) -> Option<&'a [u8]> {
        let content = self.element(0x02)?;
        let (&first, tail) = content.split_first()?;
        // A set top bit makes the integer negative.
        if first & 0x80 != 0 {
            return None;
        }
        // A leading zero is allowed only to clear the top bit of the next byte.
        match tail.first() {
            Some(&next) if first == 0 && next & 0x80 == 0 => None,
            Some(_) if first == 0 => Some(tail),
            _ => Some(content),
        }
    }

    /// Reads a whole ECDSA signature, the SEQUENCE of r and s of SEC 1, appendix C.8.
    ///
    /// Returns r || s, each left-padded to the given width, or none on any defect.
    pub(crate) fn ecdsa_signature(bytes: &'a [u8], width: usize) -> Option<Vec<u8>> {
        let mut outer = Self::new(bytes);
        let mut body = outer.sequence()?;
        if !outer.is_empty() {
            return None;
        }
        let r = body.integer()?;
        let s = body.integer()?;
        if !body.is_empty() || r.len() > width || s.len() > width {
            return None;
        }
        let mut compact = vec![0_u8; 2 * width];
        compact[width - r.len()..width].copy_from_slice(r);
        compact[2 * width - s.len()..].copy_from_slice(s);
        Some(compact)
    }
}
