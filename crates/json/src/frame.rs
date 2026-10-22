//! The containers a parse holds open on its explicit stack.

use std::mem;

use crate::{ErrorKind, Json, Object, ParseError};

/// An array or object whose closing bracket is still ahead.
pub(crate) enum Frame {
    /// An open array and the items read so far.
    Array(Vec<Json>),

    /// An open object.
    Object(OpenObject),
}

impl Frame {
    /// The byte that closes this container.
    pub(crate) const fn closer(&self) -> u8 {
        match self {
            Self::Array(_) => b']',
            Self::Object(_) => b'}',
        }
    }

    /// Attaches a complete value as the next item, or as the value of the pending member.
    pub(crate) fn push(&mut self, value: Json) {
        match self {
            Self::Array(items) => items.push(value),
            Self::Object(object) => object.push(value),
        }
    }

    /// Turns a closed container into its value.
    ///
    /// An object's names are checked for uniqueness here, once all are known.
    pub(crate) fn close(self) -> Result<Json, ParseError> {
        match self {
            Self::Array(items) => Ok(Json::Array(items)),
            Self::Object(object) => object.close(),
        }
    }
}

/// An object being read, with the name of the member whose value comes next.
pub(crate) struct OpenObject {
    /// Members read so far.
    object: Object,
    /// Name of the member whose value is being read.
    name: String,
    /// Byte offset of each member name, in member order.
    name_offsets: Vec<usize>,
}

impl OpenObject {
    /// An object whose first member name was just read at the given offset.
    pub(crate) fn new(name: String, offset: usize) -> Self {
        Self {
            object: Object::new(),
            name,
            name_offsets: vec![offset],
        }
    }

    /// Records the name of the next member, read at the given offset.
    pub(crate) fn next_name(&mut self, name: String, offset: usize) {
        self.name = name;
        self.name_offsets.push(offset);
    }

    /// Attaches the value of the pending member.
    fn push(&mut self, value: Json) {
        self.object.push_unchecked(mem::take(&mut self.name), value);
    }

    /// The finished object, rejected when it repeats a member name.
    ///
    /// Sorting member positions by name brings equal names together in O(n log n).
    /// A hostile object with a hundred thousand members then costs milliseconds, not hours.
    ///
    /// The reported offset is the earliest second occurrence in the document.
    ///
    /// ```text
    ///     {"b":1, "a":2, "b":3}        names start at offsets 1, 8, 15
    ///     sorted by name: a(8) b(1) b(15)
    ///     b repeats -> error at offset 15
    /// ```
    fn close(self) -> Result<Json, ParseError> {
        let members = self.object.members();

        // Positions 0..n, ordered by member name; a stable sort keeps document order among equals.
        let mut order: Vec<usize> = (0..members.len()).collect();
        order.sort_by(|&left, &right| members[left].0.cmp(&members[right].0));

        // Neighbours with equal names are duplicates.
        // The later of the pair, in document order, is the repeated one.
        let first_repeat = order
            .windows(2)
            .filter(|pair| members[pair[0]].0 == members[pair[1]].0)
            .map(|pair| pair[1])
            .min_by_key(|&position| self.name_offsets[position]);

        match first_repeat {
            None => Ok(Json::Object(self.object)),
            Some(position) => Err(ParseError {
                offset: self.name_offsets[position],
                kind: ErrorKind::DuplicateKey(members[position].0.clone()),
            }),
        }
    }
}
