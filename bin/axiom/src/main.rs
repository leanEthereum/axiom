//! Axiom: an Ethereum consensus client.

mod account;
mod cli;
mod database;
mod manager;
mod network;
mod run;
mod startup;
mod validator;

use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};

use tracing::error;

use crate::{
    cli::{Cli, Command},
    database::{DATABASE_USAGE, DatabaseCommand},
};

/// Exit status for a command line that cannot be used.
const USAGE_ERROR: u8 = 2;

fn main() -> ExitCode {
    let command = match Cli::parse(env::args().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            // Logging is not set up yet, so the error goes straight to the terminal.
            let _unwritable = writeln!(io::stderr(), "error: {error}\n\n{}", Cli::usage());
            return ExitCode::from(USAGE_ERROR);
        }
    };
    match command {
        Command::Help => {
            let _unwritable = write!(io::stdout(), "{}", Cli::usage());
            ExitCode::SUCCESS
        }
        Command::Database(command) => match command {
            DatabaseCommand::Help => {
                let _unwritable = write!(io::stdout(), "{DATABASE_USAGE}");
                ExitCode::SUCCESS
            }
            DatabaseCommand::Run(run) => match run.execute() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    let _unwritable = writeln!(io::stderr(), "error: {error}");
                    ExitCode::FAILURE
                }
            },
        },
        Command::Version => {
            let _unwritable = writeln!(io::stdout(), "axiom {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Account(account) => match account.execute() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _unwritable = writeln!(io::stderr(), "error: {error}");
                ExitCode::FAILURE
            }
        },
        Command::Manager(manager) => match manager.execute() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _unwritable = writeln!(io::stderr(), "error: {error}");
                ExitCode::FAILURE
            }
        },
        Command::Validator(validator) => match validator.execute() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                error!(%error, "validator client failed");
                ExitCode::FAILURE
            }
        },
        Command::Run(run) => match run.execute() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                error!(%error, "node failed");
                ExitCode::FAILURE
            }
        },
    }
}
