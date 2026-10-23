//! Client identities, as engine_getClientVersionV1 exchanges them.
//!
//! Defined in `src/engine/identification.md`.
//!
//! ```text
//!     {"code":"GE","name":"go-ethereum","version":"v1.14.0","commit":"0xfa4ff922"}
//! ```

use axiom_json::{Data, Json};

use super::{Fields, JsonCodec, Reader};
use crate::WireError;

/// A client's identity: its two-letter code, its name and version, and its build's commit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientVersion {
    /// Two letters naming the client, such as `GE`.
    pub code: String,
    /// The client's human-readable name.
    pub name: String,
    /// The version string of the build.
    pub version: String,
    /// The first four bytes of the build's commit.
    pub commit: [u8; 4],
}

impl ClientVersion {
    /// The first two bytes of the commit as four lowercase hex digits, as graffiti carries them.
    #[must_use]
    pub fn commit_prefix(&self) -> String {
        // The DATA form is 0x and eight digits; graffiti keeps the first four digits.
        self.commit.to_data()[2..6].to_owned()
    }
}

impl JsonCodec for ClientVersion {
    fn to_json(&self) -> Json {
        Json::from([
            ("code", Json::from(self.code.as_str())),
            ("name", Json::from(self.name.as_str())),
            ("version", Json::from(self.version.as_str())),
            ("commit", Json::String(self.commit.to_data())),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            code: fields.required("code")?,
            name: fields.required("name")?,
            version: fields.required("version")?,
            commit: fields.required::<Commit>("commit")?.0,
        })
    }
}

/// The four commit bytes, as DATA.
struct Commit([u8; 4]);

impl JsonCodec for Commit {
    fn to_json(&self) -> Json {
        Json::String(self.0.to_data())
    }

    fn from_json(value: &Json) -> Result<Self, WireError> {
        Reader::new(value).data().map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_version_round_trips_and_shortens_its_commit() {
        // The example of the identification spec.
        let text =
            r#"{"code":"GE","name":"go-ethereum","version":"v1.14.0","commit":"0xFA4FF922"}"#;
        let version = ClientVersion::from_json(&Json::parse(text).unwrap()).unwrap();
        assert_eq!(
            version,
            ClientVersion {
                code: "GE".to_owned(),
                name: "go-ethereum".to_owned(),
                version: "v1.14.0".to_owned(),
                commit: [0xfa, 0x4f, 0xf9, 0x22],
            }
        );
        assert_eq!(
            ClientVersion::from_json(&version.to_json()),
            Ok(version.clone())
        );

        // Graffiti keeps two bytes of the commit, in lowercase.
        assert_eq!(version.commit_prefix(), "fa4f");

        // A commit of another length is not a commit.
        let short = r#"{"code":"GE","name":"g","version":"v","commit":"0xfa4f"}"#;
        assert!(ClientVersion::from_json(&Json::parse(short).unwrap()).is_err());
    }
}
