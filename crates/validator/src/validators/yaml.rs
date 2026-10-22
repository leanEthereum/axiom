//! Typed reads and writes of one YAML mapping, for the files an operator may edit by hand.

use std::mem;

use axiom_json::Data;
use axiom_yaml::{Mapping, Yaml};

use crate::validators::FieldError;

/// One mapping of a hand-editable file, read field by field.
///
/// A field written as null reads as absent, as an operator clearing a value expects.
#[derive(Clone, Copy, Debug)]
pub(crate) struct YamlFields<'a> {
    /// The mapping.
    mapping: &'a Mapping,
}

impl<'a> YamlFields<'a> {
    /// The fields of a node that must be a mapping.
    pub(crate) fn of(node: &'a Yaml) -> Result<Self, FieldError> {
        node.as_mapping()
            .map(|mapping| Self { mapping })
            .ok_or_else(|| FieldError::new("entry", "a mapping"))
    }

    /// A field's node, absent when missing or null.
    pub(crate) fn node(self, field: &'static str) -> Option<&'a Yaml> {
        self.mapping.get(field).filter(|node| !node.is_null())
    }

    /// A text field.
    pub(crate) fn text(self, field: &'static str) -> Result<Option<&'a str>, FieldError> {
        self.node(field)
            .map(|node| node.as_str().ok_or_else(|| FieldError::new(field, "text")))
            .transpose()
    }

    /// A text field that must be present.
    pub(crate) fn required_text(self, field: &'static str) -> Result<&'a str, FieldError> {
        self.text(field)?
            .ok_or_else(|| FieldError::new(field, "text"))
    }

    /// A decimal integer field.
    pub(crate) fn u64(self, field: &'static str) -> Result<Option<u64>, FieldError> {
        self.node(field)
            .map(|node| {
                node.as_u64()
                    .ok_or_else(|| FieldError::new(field, "a decimal integer"))
            })
            .transpose()
    }

    /// A boolean field.
    pub(crate) fn bool(self, field: &'static str) -> Result<Option<bool>, FieldError> {
        self.node(field)
            .map(|node| {
                node.as_bool()
                    .ok_or_else(|| FieldError::new(field, "true or false"))
            })
            .transpose()
    }

    /// A field of 0x-prefixed hex bytes.
    pub(crate) fn bytes(self, field: &'static str) -> Result<Option<Vec<u8>>, FieldError> {
        self.node(field)
            .map(|node| {
                node.as_hex_bytes()
                    .ok_or_else(|| FieldError::new(field, "0x-prefixed hex"))
            })
            .transpose()
    }

    /// A field of exactly N 0x-prefixed hex bytes.
    pub(crate) fn array<const N: usize>(
        self,
        field: &'static str,
    ) -> Result<Option<[u8; N]>, FieldError> {
        self.node(field)
            .map(|node| {
                node.as_hex_array()
                    .ok_or_else(|| FieldError::new(field, "0x-prefixed hex of the right length"))
            })
            .transpose()
    }

    /// A sequence field.
    pub(crate) fn sequence(self, field: &'static str) -> Result<Option<&'a [Yaml]>, FieldError> {
        self.node(field)
            .map(|node| {
                node.as_sequence()
                    .ok_or_else(|| FieldError::new(field, "a sequence"))
            })
            .transpose()
    }
}

/// A mapping being written, skipping absent fields so the file stays short.
#[derive(Debug, Default)]
pub(crate) struct YamlWriter {
    /// The entries so far.
    mapping: Mapping,
}

impl YamlWriter {
    /// Writes a node.
    pub(crate) fn node(&mut self, field: &str, node: Yaml) -> &mut Self {
        self.mapping.insert(field, node);
        self
    }

    /// Writes text.
    pub(crate) fn text(&mut self, field: &str, text: impl Into<String>) -> &mut Self {
        self.node(field, Yaml::String(text.into()))
    }

    /// Writes an integer, when present.
    pub(crate) fn u64(&mut self, field: &str, value: Option<u64>) -> &mut Self {
        match value {
            Some(value) => self.text(field, value.to_string()),
            None => self,
        }
    }

    /// Writes a boolean, when present.
    pub(crate) fn bool(&mut self, field: &str, value: Option<bool>) -> &mut Self {
        match value {
            Some(value) => self.node(field, Yaml::Bool(value)),
            None => self,
        }
    }

    /// Writes bytes as 0x-prefixed hex, when present.
    pub(crate) fn bytes(&mut self, field: &str, value: Option<&[u8]>) -> &mut Self {
        match value {
            Some(bytes) => self.text(field, bytes.to_data()),
            None => self,
        }
    }

    /// The finished mapping.
    pub(crate) fn finish(&mut self) -> Yaml {
        Yaml::Mapping(mem::take(&mut self.mapping))
    }
}
