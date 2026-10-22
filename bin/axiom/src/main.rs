//! Axiom: an Ethereum consensus client.

mod cli;
mod run;

use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};

use tracing::error;

use crate::cli::{Cli, Command, USAGE};

/// Exit status for a command line that cannot be used.
const USAGE_ERROR: u8 = 2;

fn main() -> ExitCode {
    let command = match Cli::parse(env::args().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            // Logging is not set up yet, so the error goes straight to the terminal.
            let _unwritable = writeln!(io::stderr(), "error: {error}\n\n{USAGE}");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    match command {
        Command::Help => {
            let _unwritable = write!(io::stdout(), "{USAGE}");
            ExitCode::SUCCESS
        }
        Command::Version => {
            let _unwritable = writeln!(io::stdout(), "axiom {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Run(run) => match run.execute() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                error!(%error, "node failed");
                ExitCode::FAILURE
            }
        },
    }
}
