//! What an operator chooses about the slasher, and the layout it implies.

use axiom_types::{Epoch, ValidatorIndex};

use crate::ConfigError;

/// Sizes of the slasher's history and of the chunks it stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlasherConfig {
    /// Epochs of votes kept, counted back from the current epoch.
    ///
    /// A surround vote whose older vote left the window goes unseen.
    pub history_length: u64,

    /// Epochs per span chunk.
    pub chunk_size: u64,

    /// Validators per span chunk.
    pub validator_chunk_size: u64,

    /// Validators per chunk of the table naming each validator's vote for a target epoch.
    pub record_chunk_size: u64,

    /// Epochs between two passes that delete history older than the window.
    pub prune_period: u64,
}

impl SlasherConfig {
    /// Longest history a 16-bit cell can measure distances in.
    ///
    /// A cell holds a target's distance from its epoch, below the history length.
    /// The all-ones value is reserved to mean no vote.
    pub const MAX_HISTORY_LENGTH: u64 = u16::MAX as u64;

    /// Checks the sizes and returns the layout they describe.
    ///
    /// # Errors
    ///
    /// Fails when a size is zero, the history does not split into whole chunks, or is too long.
    pub const fn geometry(&self) -> Result<Geometry, ConfigError> {
        let sizes = [
            ("history length", self.history_length),
            ("chunk size", self.chunk_size),
            ("validator chunk size", self.validator_chunk_size),
            ("record chunk size", self.record_chunk_size),
            ("prune period", self.prune_period),
        ];
        let mut index = 0;
        while index < sizes.len() {
            if sizes[index].1 == 0 {
                return Err(ConfigError::Zero {
                    field: sizes[index].0,
                });
            }
            index += 1;
        }
        if !self.history_length.is_multiple_of(self.chunk_size) {
            return Err(ConfigError::Indivisible {
                history: self.history_length,
                chunk: self.chunk_size,
            });
        }
        if self.history_length > Self::MAX_HISTORY_LENGTH {
            return Err(ConfigError::HistoryTooLong {
                history: self.history_length,
                limit: Self::MAX_HISTORY_LENGTH,
            });
        }
        Ok(Geometry {
            history_length: self.history_length,
            chunk_size: self.chunk_size,
            validator_chunk_size: self.validator_chunk_size,
            record_chunk_size: self.record_chunk_size,
        })
    }
}

impl Default for SlasherConfig {
    /// A history of 4096 epochs, about eighteen days.
    ///
    /// It spans the weak subjectivity period of a mainnet-sized validator set.
    /// A surround vote reaching further back attacks nodes that must sync from a checkpoint anyway.
    /// See the phase0 weak subjectivity guide.
    ///
    /// Span chunks of 16 epochs by 1024 validators weigh 32 KiB before compression.
    /// The store keeps every key in memory, so larger chunks keep the index small.
    /// A mainnet registry then needs about half a million span keys.
    fn default() -> Self {
        Self {
            history_length: 4096,
            chunk_size: 16,
            validator_chunk_size: 1024,
            record_chunk_size: 16384,
            prune_period: 1,
        }
    }
}

/// A checked layout of the span arrays and vote records.
///
/// # Overview
///
/// Each validator has two arrays over the epochs of the window.
/// Epoch e sits at column e mod H, so the window reuses its cells as it slides.
/// The arrays are cut into chunks of C epochs by K validators, one database value each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Epochs of history.
    history_length: u64,
    /// Epochs per span chunk.
    chunk_size: u64,
    /// Validators per span chunk.
    validator_chunk_size: u64,
    /// Validators per record chunk.
    record_chunk_size: u64,
}

impl Geometry {
    /// Bytes of the layout as stored beside the data it describes.
    pub(crate) const ENCODED_LEN: usize = 32;

    /// The earliest epoch of the window that ends at an epoch.
    #[must_use]
    pub const fn window_start(self, current: Epoch) -> Epoch {
        current.saturating_sub(self.history_length - 1)
    }

    /// Whether an epoch lies in the window that ends at an epoch.
    #[must_use]
    pub const fn in_window(self, epoch: Epoch, current: Epoch) -> bool {
        epoch.0 >= self.window_start(current).0 && epoch.0 <= current.0
    }

    /// Epochs of history.
    #[must_use]
    pub const fn history_length(self) -> u64 {
        self.history_length
    }

    /// The span chunk row that holds a validator.
    pub(crate) const fn row(self, validator: ValidatorIndex) -> u64 {
        validator.0 / self.validator_chunk_size
    }

    /// The span chunk column that holds an epoch.
    pub(crate) const fn column(self, epoch: Epoch) -> u64 {
        epoch.0 % self.history_length / self.chunk_size
    }

    /// Cells in one span chunk.
    pub(crate) const fn span_cells(self) -> usize {
        (self.validator_chunk_size * self.chunk_size) as usize
    }

    /// Position of a validator's cell for an epoch within its span chunk.
    ///
    /// The cells of one validator are contiguous, so a walk over epochs stays in one cache line.
    pub(crate) const fn span_cell(self, validator: ValidatorIndex, epoch: Epoch) -> usize {
        let row_offset = validator.0 % self.validator_chunk_size;
        let column_offset = epoch.0 % self.chunk_size;
        (row_offset * self.chunk_size + column_offset) as usize
    }

    /// Positions of every validator's cell for an epoch within a span chunk.
    pub(crate) fn span_epoch_cells(self, epoch: Epoch) -> impl Iterator<Item = usize> {
        let offset = (epoch.0 % self.chunk_size) as usize;
        (offset..self.span_cells()).step_by(self.chunk_size as usize)
    }

    /// The record chunk that holds a validator.
    pub(crate) const fn record_chunk(self, validator: ValidatorIndex) -> u64 {
        validator.0 / self.record_chunk_size
    }

    /// Cells in one record chunk.
    pub(crate) const fn record_cells(self) -> usize {
        self.record_chunk_size as usize
    }

    /// Position of a validator within its record chunk.
    pub(crate) const fn record_cell(self, validator: ValidatorIndex) -> usize {
        (validator.0 % self.record_chunk_size) as usize
    }

    /// The layout as four big-endian words.
    pub(crate) fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0; Self::ENCODED_LEN];
        let words = [
            self.history_length,
            self.chunk_size,
            self.validator_chunk_size,
            self.record_chunk_size,
        ];
        for (slot, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *slot = word.to_be_bytes();
        }
        bytes
    }

    /// The layout from its stored form, if the bytes have the right length.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return None;
        }
        let mut words = bytes
            .as_chunks::<8>()
            .0
            .iter()
            .copied()
            .map(u64::from_be_bytes);
        Some(Self {
            history_length: words.next()?,
            chunk_size: words.next()?,
            validator_chunk_size: words.next()?,
            record_chunk_size: words.next()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_layout_is_valid() {
        // 4096 epochs split into 256 chunks of 16.
        let geometry = SlasherConfig::default()
            .geometry()
            .expect("defaults are valid");
        assert_eq!(geometry.history_length(), 4096);
        assert_eq!(geometry.span_cells(), 16 * 1024);
    }

    #[test]
    fn a_zero_size_is_refused() {
        let config = SlasherConfig {
            validator_chunk_size: 0,
            ..SlasherConfig::default()
        };
        assert_eq!(
            config.geometry(),
            Err(ConfigError::Zero {
                field: "validator chunk size"
            })
        );
    }

    #[test]
    fn a_history_of_partial_chunks_is_refused() {
        // 100 epochs do not split into chunks of 16.
        let config = SlasherConfig {
            history_length: 100,
            ..SlasherConfig::default()
        };
        assert_eq!(
            config.geometry(),
            Err(ConfigError::Indivisible {
                history: 100,
                chunk: 16
            })
        );
    }

    #[test]
    fn a_history_beyond_sixteen_bits_is_refused() {
        // 65536 epochs need a distance of 65535, the reserved value.
        let config = SlasherConfig {
            history_length: 65536,
            chunk_size: 1,
            ..SlasherConfig::default()
        };
        assert_eq!(
            config.geometry(),
            Err(ConfigError::HistoryTooLong {
                history: 65536,
                limit: 65535
            })
        );
    }

    #[test]
    fn the_window_slides_over_its_columns() {
        // History 64 in chunks of 16: epochs 70 and 6 share column 0.
        let geometry = SlasherConfig {
            history_length: 64,
            ..SlasherConfig::default()
        }
        .geometry()
        .expect("valid");
        assert_eq!(geometry.column(Epoch(70)), geometry.column(Epoch(6)));
        assert_eq!(geometry.window_start(Epoch(70)), Epoch(7));
        assert!(geometry.in_window(Epoch(7), Epoch(70)));
        assert!(!geometry.in_window(Epoch(6), Epoch(70)));
        // Early in the chain the window starts at genesis.
        assert_eq!(geometry.window_start(Epoch(3)), Epoch(0));
    }

    #[test]
    fn the_layout_round_trips_through_its_stored_form() {
        let geometry = SlasherConfig::default().geometry().expect("valid");
        assert_eq!(Geometry::decode(&geometry.encode()), Some(geometry));
        assert_eq!(Geometry::decode(&[0; 31]), None);
    }
}
