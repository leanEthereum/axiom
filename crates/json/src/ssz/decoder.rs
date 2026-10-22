//! From JSON to SSZ bytes, along a schema.

use std::fmt::Write;

use axiom_ssz::{BYTES_PER_LENGTH_OFFSET, Field, Schema, UnionOption};

use super::{SszJsonError, uint::LittleEndian};
use crate::{Data, Json, Object};

/// One step from a value to a value inside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// A container's field, or a union's member.
    Field(&'static str),
    /// A sequence's element.
    Index(usize),
}

/// Writes the SSZ encoding a JSON value describes, remembering where it is for errors.
///
/// Only the shape is checked here: kinds, digits, lengths, and limits.
/// The SSZ decoder of the target type checks the rest, such as bitlist delimiters.
#[derive(Debug, Default)]
pub(crate) struct JsonDecoder {
    /// The steps from the root to the value being read.
    path: Vec<Step>,
}

impl JsonDecoder {
    /// A decoder at the root value.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The SSZ encoding of a JSON value of the schema's type.
    ///
    /// # Errors
    ///
    /// Fails when the JSON strays from the schema, naming where.
    pub(crate) fn value(&mut self, schema: &Schema, json: &Json) -> Result<Vec<u8>, SszJsonError> {
        match *schema {
            Schema::Boolean => match json {
                Json::Bool(value) => Ok(vec![u8::from(*value)]),
                other => Err(self.wrong_kind("a boolean", other)),
            },
            Schema::Uint { bytes } => self.uint(json, bytes),
            Schema::ByteVector { length } => self.fixed_bytes(json, length),
            Schema::BitVector { length } => self.fixed_bytes(json, length.div_ceil(8)),
            Schema::ByteList { limit } => {
                let bytes = self.hex(json)?;
                self.within(limit, bytes.len())?;
                Ok(bytes)
            }
            // A bitlist's encoding carries its delimiter bit, so the type's decoder checks the limit.
            // An unbounded byte list has no limit to check.
            Schema::BitList { .. } | Schema::ProgressiveBitList | Schema::ProgressiveByteList => {
                self.hex(json)
            }
            Schema::Vector { element, length } => {
                let items = self.array(json)?;
                if items.len() != length {
                    return Err(SszJsonError::WrongLength {
                        path: self.path(),
                        expected: length,
                        actual: items.len(),
                    });
                }
                self.sequence(element, items)
            }
            Schema::List { element, limit } => {
                let items = self.array(json)?;
                self.within(limit, items.len())?;
                self.sequence(element, items)
            }
            Schema::ProgressiveList { element } => {
                let items = self.array(json)?;
                self.sequence(element, items)
            }
            Schema::Container { fields } => match json {
                Json::Object(object) => self.container(fields, object),
                other => Err(self.wrong_kind("an object", other)),
            },
            Schema::Union { options } => match json {
                Json::Object(object) => self.union(options, object),
                other => Err(self.wrong_kind("an object", other)),
            },
        }
    }

    /// An unsigned integer, from a decimal string or a JSON number.
    fn uint(&self, json: &Json, width: usize) -> Result<Vec<u8>, SszJsonError> {
        let text = match json {
            Json::String(text) => text.as_str(),
            Json::Number(number) => number.as_str(),
            other => return Err(self.wrong_kind("a decimal string", other)),
        };
        LittleEndian::from_decimal(text, width)
            .map(LittleEndian::into_bytes)
            .ok_or_else(|| SszJsonError::InvalidUint {
                path: self.path(),
                text: text.to_owned(),
                bits: width * 8,
            })
    }

    /// Hex bytes of an exact length.
    fn fixed_bytes(&self, json: &Json, length: usize) -> Result<Vec<u8>, SszJsonError> {
        let bytes = self.hex(json)?;
        if bytes.len() != length {
            return Err(SszJsonError::WrongLength {
                path: self.path(),
                expected: length,
                actual: bytes.len(),
            });
        }
        Ok(bytes)
    }

    /// Hex bytes of any length.
    fn hex(&self, json: &Json) -> Result<Vec<u8>, SszJsonError> {
        let Json::String(text) = json else {
            return Err(self.wrong_kind("a hex string", json));
        };
        Vec::from_data(text).map_err(|source| SszJsonError::InvalidHex {
            path: self.path(),
            source,
        })
    }

    /// The items of an array.
    fn array<'j>(&self, json: &'j Json) -> Result<&'j [Json], SszJsonError> {
        match json {
            Json::Array(items) => Ok(items),
            other => Err(self.wrong_kind("an array", other)),
        }
    }

    /// Checks a count against a limit.
    fn within(&self, limit: usize, actual: usize) -> Result<(), SszJsonError> {
        if actual > limit {
            return Err(SszJsonError::TooLong {
                path: self.path(),
                limit,
                actual,
            });
        }
        Ok(())
    }

    /// The encoding of a vector's or list's elements.
    fn sequence(&mut self, element: &Schema, items: &[Json]) -> Result<Vec<u8>, SszJsonError> {
        let mut parts = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            self.path.push(Step::Index(index));
            parts.push(self.value(element, item)?);
            self.path.pop();
        }
        let variable = element.fixed_size().is_none();
        Ok(Self::join(parts.into_iter().map(|part| (variable, part))))
    }

    /// The encoding of a container's fields, refusing members the type does not declare.
    fn container(&mut self, fields: &[Field], object: &Object) -> Result<Vec<u8>, SszJsonError> {
        if let Some((name, _)) = object
            .iter()
            .find(|(name, _)| !fields.iter().any(|field| field.name() == name))
        {
            return Err(SszJsonError::UnknownField {
                path: self.path(),
                field: name.clone(),
            });
        }
        let mut parts = Vec::with_capacity(fields.len());
        for field in fields {
            let json = object
                .get(field.name())
                .ok_or_else(|| SszJsonError::MissingField {
                    path: self.path(),
                    field: field.name(),
                })?;
            self.path.push(Step::Field(field.name()));
            parts.push((field.size().is_none(), self.value(field.schema(), json)?));
            self.path.pop();
        }
        Ok(Self::join(parts.into_iter()))
    }

    /// The encoding of a union: its selector byte, then the option's encoding.
    fn union(&mut self, options: &[UnionOption], object: &Object) -> Result<Vec<u8>, SszJsonError> {
        const MEMBERS: [&str; 2] = ["selector", "data"];
        if let Some((name, _)) = object
            .iter()
            .find(|(name, _)| !MEMBERS.contains(&name.as_str()))
        {
            return Err(SszJsonError::UnknownField {
                path: self.path(),
                field: name.clone(),
            });
        }
        let member = |field: &'static str| {
            object.get(field).ok_or_else(|| SszJsonError::MissingField {
                path: self.path(),
                field,
            })
        };
        let (selector, data) = (member("selector")?, member("data")?);

        self.path.push(Step::Field("selector"));
        let byte = self.uint(selector, 1)?;
        self.path.pop();
        let option = options
            .iter()
            .find(|option| [option.selector()] == byte.as_slice())
            .ok_or_else(|| SszJsonError::UnknownSelector {
                path: self.path(),
                selector: byte.first().copied().unwrap_or_default().to_string(),
            })?;

        self.path.push(Step::Field("data"));
        let mut bytes = byte;
        bytes.extend(self.value(option.schema(), data)?);
        self.path.pop();
        Ok(bytes)
    }

    /// Lays out parts as SSZ does: fixed parts inline, variable parts behind offsets.
    fn join(parts: impl Iterator<Item = (bool, Vec<u8>)>) -> Vec<u8> {
        let parts: Vec<(bool, Vec<u8>)> = parts.collect();
        let fixed_len: usize = parts
            .iter()
            .map(|(variable, part)| {
                if *variable {
                    BYTES_PER_LENGTH_OFFSET
                } else {
                    part.len()
                }
            })
            .sum();
        let total = fixed_len
            + parts
                .iter()
                .filter(|(variable, _)| *variable)
                .map(|(_, part)| part.len())
                .sum::<usize>();
        let mut out = Vec::with_capacity(total);
        let mut next_offset = fixed_len;
        for (variable, part) in &parts {
            if *variable {
                // An offset past 4 GiB cannot be written; it saturates, and the type's decoder refuses it.
                let offset = u32::try_from(next_offset).unwrap_or(u32::MAX);
                out.extend_from_slice(&offset.to_le_bytes());
                next_offset += part.len();
            } else {
                out.extend_from_slice(part);
            }
        }
        for (_, part) in parts.iter().filter(|(variable, _)| *variable) {
            out.extend_from_slice(part);
        }
        out
    }

    /// An error for a value of the wrong JSON kind.
    fn wrong_kind(&self, expected: &'static str, found: &Json) -> SszJsonError {
        SszJsonError::WrongKind {
            path: self.path(),
            expected,
            found: found.kind(),
        }
    }

    /// The current place, such as `$.message.body.deposits[2]`.
    fn path(&self) -> String {
        let mut path = String::from("$");
        for step in &self.path {
            // Writing to a string cannot fail.
            let _ = match step {
                Step::Field(name) => write!(path, ".{name}"),
                Step::Index(index) => write!(path, "[{index}]"),
            };
        }
        path
    }
}
