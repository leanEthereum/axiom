//! A strict parser for the YAML that Ethereum consensus configs and test vectors use.
//!
//! # Overview
//!
//! The supported subset covers every file of the consensus spec tests:
//!
//! - block mappings and sequences, including compact and indentless forms,
//! - flow sequences and mappings, spanning lines,
//! - plain, single-quoted, and double-quoted scalars, folded across lines,
//! - comments, and the `---` and `...` document markers.
//!
//! Anchors, aliases, tags, block scalars, directives, explicit keys, and multiple documents are rejected.
//! A rejection names the feature, so a new vector shape fails loudly instead of misreading.
//!
//! Scalars keep their text.
//! Only plain nulls and booleans resolve, per the YAML 1.2 core schema.
//! Typed views read decimal integers and `0x` hex bytes from the text on demand.

mod char_class;
mod emitter;
mod error;
mod mapping;
mod parser;
mod scanner;
mod value;

pub use error::{ErrorKind, ParseError, Unsupported};
pub use mapping::{Iter, Mapping};
pub use value::Yaml;
