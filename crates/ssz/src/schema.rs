//! The shape of an SSZ type, as data a program can walk.
//!
//! # Overview
//!
//! Every SSZ type is built from a few kinds: basic values, byte strings, bitfields,
//! sequences, containers, and unions.
//! A schema records which kind a type is, and recursively the kinds inside it.
//!
//! Codecs that only need the shape, such as the JSON mapping, walk the schema.
//! They need no code per type, so a new container gets them by naming its fields.
//!
//! The kinds follow the type definitions of the SSZ specification.

use crate::{BYTES_PER_LENGTH_OFFSET, Ssz};

/// The kind of an SSZ type and, for composite kinds, the kinds it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schema {
    /// A boolean, one byte.
    Boolean,

    /// An unsigned integer of this many bytes, little-endian.
    Uint {
        /// Width in bytes: 1, 2, 4, 8, 16, or 32.
        bytes: usize,
    },

    /// A fixed number of bytes.
    ByteVector {
        /// Number of bytes.
        length: usize,
    },

    /// Up to a limit of bytes.
    ByteList {
        /// Most bytes allowed.
        limit: usize,
    },

    /// Any number of bytes, per EIP-7916.
    ProgressiveByteList,

    /// A fixed number of bits, packed eight to a byte.
    BitVector {
        /// Number of bits.
        length: usize,
    },

    /// Up to a limit of bits, followed by a delimiting set bit.
    BitList {
        /// Most bits allowed.
        limit: usize,
    },

    /// Any number of bits, followed by a delimiting set bit, per EIP-7916.
    ProgressiveBitList,

    /// A fixed number of elements of one type.
    Vector {
        /// The element type.
        element: &'static Self,
        /// Number of elements.
        length: usize,
    },

    /// Up to a limit of elements of one type.
    List {
        /// The element type.
        element: &'static Self,
        /// Most elements allowed.
        limit: usize,
    },

    /// Any number of elements of one type, per EIP-7916.
    ProgressiveList {
        /// The element type.
        element: &'static Self,
    },

    /// Named fields in declaration order.
    Container {
        /// The fields.
        fields: &'static [Field],
    },

    /// One option among several, under a selector byte, per EIP-8016.
    Union {
        /// The options, by ascending selector.
        options: &'static [UnionOption],
    },
}

impl Schema {
    /// Encoded size of every value, when the type is fixed-size.
    ///
    /// It agrees with the fixed size each type declares.
    #[must_use]
    pub const fn fixed_size(&self) -> Option<usize> {
        match *self {
            Self::Boolean => Some(1),
            Self::Uint { bytes } => Some(bytes),
            Self::ByteVector { length } => Some(length),
            // Bits round up to whole bytes.
            Self::BitVector { length } => Some(length.div_ceil(8)),
            Self::Vector { element, length } => match element.fixed_size() {
                Some(size) => Some(size * length),
                None => None,
            },
            Self::Container { fields } => {
                let mut total = 0;
                let mut index = 0;
                while index < fields.len() {
                    match fields[index].size {
                        Some(size) => total += size,
                        None => return None,
                    }
                    index += 1;
                }
                Some(total)
            }
            Self::ByteList { .. }
            | Self::ProgressiveByteList
            | Self::BitList { .. }
            | Self::ProgressiveBitList
            | Self::List { .. }
            | Self::ProgressiveList { .. }
            | Self::Union { .. } => None,
        }
    }

    /// The type of a container's field, by name; nothing for another kind or an unknown name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&'static Self> {
        match self {
            Self::Container { fields } => fields
                .iter()
                .find(|field| field.name == name)
                .map(|field| field.schema),
            _ => None,
        }
    }

    /// Bytes a value of this type takes in the fixed part of its parent.
    ///
    /// A variable-size value is replaced there by an offset.
    #[must_use]
    pub const fn fixed_part_size(&self) -> usize {
        match self.fixed_size() {
            Some(size) => size,
            None => BYTES_PER_LENGTH_OFFSET,
        }
    }
}

/// A named field of a container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field's name, as the specification spells it.
    name: &'static str,
    /// The field's type.
    schema: &'static Schema,
    /// The field's fixed size, empty when it is variable-size.
    size: Option<usize>,
}

impl Field {
    /// A field of the given type.
    #[must_use]
    pub const fn new<T: Ssz>(name: &'static str) -> Self {
        Self {
            name,
            schema: &T::SCHEMA,
            size: T::FIXED_SIZE,
        }
    }

    /// The field's name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The field's type.
    #[must_use]
    pub const fn schema(&self) -> &'static Schema {
        self.schema
    }

    /// The field's fixed size, empty when it is variable-size.
    #[must_use]
    pub const fn size(&self) -> Option<usize> {
        self.size
    }
}

/// One option of a union, under its selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnionOption {
    /// The selector byte naming the option.
    selector: u8,
    /// The option's type.
    schema: &'static Schema,
}

impl UnionOption {
    /// An option of the given type under a selector.
    #[must_use]
    pub const fn new<T: Ssz>(selector: u8) -> Self {
        Self {
            selector,
            schema: &T::SCHEMA,
        }
    }

    /// The selector byte.
    #[must_use]
    pub const fn selector(&self) -> u8 {
        self.selector
    }

    /// The option's type.
    #[must_use]
    pub const fn schema(&self) -> &'static Schema {
        self.schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BitVector, ByteList, Const, List, Root, Vector};

    #[test]
    fn fixed_sizes_agree_with_the_types() {
        // Each schema's size matches the size the type itself declares.
        assert_eq!(u64::SCHEMA.fixed_size(), u64::FIXED_SIZE);
        assert_eq!(Root::SCHEMA.fixed_size(), Some(32));
        assert_eq!(BitVector::<Const<9>>::SCHEMA.fixed_size(), Some(2));
        assert_eq!(Vector::<u16, Const<3>>::SCHEMA.fixed_size(), Some(6));
        assert_eq!(ByteList::<Const<4>>::SCHEMA.fixed_size(), None);

        // A vector of variable-size elements is itself variable-size.
        assert_eq!(
            Vector::<List<u8, Const<2>>, Const<3>>::SCHEMA.fixed_size(),
            None
        );

        // An offset stands in for a variable-size value in its parent.
        assert_eq!(ByteList::<Const<4>>::SCHEMA.fixed_part_size(), 4);
        assert_eq!(Root::SCHEMA.fixed_part_size(), 32);
    }

    #[test]
    fn fields_are_found_by_name() {
        // A container with a u64 and a list, looked up by each name and a wrong one.
        const FIELDS: &[Field] = &[
            Field::new::<u64>("slot"),
            Field::new::<List<u8, Const<2>>>("data"),
        ];
        let container = Schema::Container { fields: FIELDS };
        assert_eq!(container.field("slot"), Some(&u64::SCHEMA));
        assert_eq!(container.field("data"), Some(&List::<u8, Const<2>>::SCHEMA));
        assert_eq!(container.field("root"), None);

        // A non-container has no fields.
        assert_eq!(u64::SCHEMA.field("slot"), None);
    }
}
