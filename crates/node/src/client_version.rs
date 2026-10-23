//! This client's identity, as the node API and the engine API report it.

use axiom_execution::ClientVersion;
use axiom_json::Data;

/// The client's name and version, as reported to peers and tools.
pub(crate) const VERSION: &str = concat!("axiom/v", env!("CARGO_PKG_VERSION"));

/// The client's two-letter code, in the engine API's client identification format.
///
/// The engine API's list of codes has no entry for Axiom, so these are its initials.
/// See the identification section of the engine API.
pub(crate) const CLIENT_CODE: &str = "AX";

/// The first four bytes of the source commit, when the build names one.
///
/// A build without the variable reports zeros, as the identification format allows.
pub(crate) const COMMIT: &str = match option_env!("AXIOM_COMMIT") {
    Some(commit) => commit,
    None => "0x00000000",
};

/// This client's identity in the engine API's identification format.
pub(crate) fn ours() -> ClientVersion {
    ClientVersion {
        code: CLIENT_CODE.to_owned(),
        name: "Axiom".to_owned(),
        version: concat!("v", env!("CARGO_PKG_VERSION")).to_owned(),
        // A malformed build variable reads as zeros rather than failing the node.
        commit: <[u8; 4]>::from_data(COMMIT).unwrap_or_default(),
    }
}
