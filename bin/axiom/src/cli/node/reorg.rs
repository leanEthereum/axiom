//! Proposer reorgs: whether the node's proposers orphan a late, weak head.

use axiom_node::ProposerReorgs;

use crate::cli::{CliError, arguments::Arguments};

/// The usage lines of the reorg flags.
pub(crate) const REORG_USAGE: &str = "\
    --disable-proposer-reorgs    always build on the head, never on a late head's parent
    --proposer-reorg-threshold <PERCENT>
                                 deprecated, no effect: the spec's configuration decides
    --proposer-reorg-parent-threshold <PERCENT>
                                 deprecated, no effect: the spec's configuration decides
    --proposer-reorg-epochs-since-finalization <EPOCHS>
                                 deprecated, no effect: the spec's configuration decides
    --proposer-reorg-cutoff <MILLISECONDS>
                                 deprecated, no effect: the spec's configuration decides
    --proposer-reorg-disallowed-offsets <N1,N2,...>
                                 deprecated, no effect: the spec's configuration decides
";

/// The tuning flags other clients once read, which the spec's configuration now replaces.
///
/// Each is still accepted, checked, and reported as having no effect.
const DEPRECATED: [&str; 5] = [
    "--proposer-reorg-threshold",
    "--proposer-reorg-parent-threshold",
    "--proposer-reorg-epochs-since-finalization",
    "--proposer-reorg-cutoff",
    "--proposer-reorg-disallowed-offsets",
];

/// The reorg flags as given.
#[derive(Debug, Default)]
pub(crate) struct ReorgFlags {
    /// Whether proposer reorgs are off.
    disabled: bool,
    /// The deprecated tuning flags given, in order.
    deprecated: Vec<&'static str>,
}

impl ReorgFlags {
    /// Takes a reorg flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        if flag == "--disable-proposer-reorgs" {
            self.disabled = true;
            return Ok(true);
        }
        let Some(&name) = DEPRECATED.iter().find(|name| **name == flag) else {
            return Ok(false);
        };
        let value = words.value(name)?;
        // The value is still checked, so a typo fails as it did when the flag had an effect.
        let valid = if name == "--proposer-reorg-disallowed-offsets" {
            value
                .split(',')
                .all(|offset| offset.trim().parse::<u64>().is_ok())
        } else {
            value.parse::<u64>().is_ok()
        };
        if !valid {
            return Err(CliError::InvalidValue { flag: name, value });
        }
        self.deprecated.push(name);
        Ok(true)
    }

    /// The reorg setting, and the deprecated flags given, which conflict with disabling reorgs.
    ///
    /// # Errors
    ///
    /// Fails when reorgs are disabled and a tuning flag is given too.
    pub(crate) fn resolve(self) -> Result<(ProposerReorgs, Vec<&'static str>), CliError> {
        if self.disabled {
            if let Some(flag) = self.deprecated.first() {
                return Err(CliError::Conflicts {
                    flag,
                    other: "--disable-proposer-reorgs",
                });
            }
            return Ok((ProposerReorgs::Disabled, Vec::new()));
        }
        Ok((ProposerReorgs::Enabled, self.deprecated))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(words: &[&str]) -> Result<ReorgFlags, CliError> {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = ReorgFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words)?, "{flag}");
        }
        Ok(flags)
    }

    #[test]
    fn reorgs_are_on_unless_disabled() {
        assert_eq!(
            flags(&[]).unwrap().resolve().unwrap(),
            (ProposerReorgs::Enabled, Vec::new())
        );
        assert_eq!(
            flags(&["--disable-proposer-reorgs"])
                .unwrap()
                .resolve()
                .unwrap(),
            (ProposerReorgs::Disabled, Vec::new())
        );
    }

    #[test]
    fn tuning_flags_are_checked_and_reported_deprecated() {
        let given = flags(&[
            "--proposer-reorg-threshold",
            "20",
            "--proposer-reorg-disallowed-offsets",
            "0,1",
        ])
        .unwrap();
        assert_eq!(
            given.resolve().unwrap(),
            (
                ProposerReorgs::Enabled,
                vec![
                    "--proposer-reorg-threshold",
                    "--proposer-reorg-disallowed-offsets"
                ]
            )
        );

        // A malformed value still fails, and tuning conflicts with disabling.
        assert!(matches!(
            flags(&["--proposer-reorg-cutoff", "soon"]),
            Err(CliError::InvalidValue {
                flag: "--proposer-reorg-cutoff",
                ..
            })
        ));
        assert!(matches!(
            flags(&[
                "--disable-proposer-reorgs",
                "--proposer-reorg-threshold",
                "20"
            ])
            .unwrap()
            .resolve(),
            Err(CliError::Conflicts {
                flag: "--proposer-reorg-threshold",
                other: "--disable-proposer-reorgs",
            })
        ));
    }
}
