//! Certificate times: UTCTime and GeneralizedTime, as seconds since the Unix epoch.

use super::{DerError, DerReader, DerWriter, Tag};

/// Seconds per day; X.509 times carry no leap seconds.
const SECONDS_PER_DAY: i64 = 86_400;

/// An instant in whole seconds since 1970-01-01 00:00:00 UTC, negative before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Timestamp(i64);

impl Timestamp {
    /// The instant a number of seconds after the epoch.
    pub(crate) fn from_unix_secs(seconds: u64) -> Self {
        // Every u64 below 2^63 fits; later instants clamp, far past any certificate.
        Self(i64::try_from(seconds).unwrap_or(i64::MAX))
    }

    /// Seconds since the epoch, negative before it.
    pub(crate) const fn unix_seconds(self) -> i64 {
        self.0
    }

    /// The instant at a calendar date and time of day, in UTC.
    ///
    /// # Algorithm
    ///
    /// The proleptic Gregorian day count of Hinnant, "chrono-Compatible Low-Level Date Algorithms".
    /// Shifting the year to start in March puts the leap day last.
    ///
    /// ```text
    /// era = floor(y / 400), yoe = y - 400 era
    /// doy = (153 (m + 9 mod 12) + 2) / 5 + d - 1
    /// days = 146097 era + 365 yoe + yoe / 4 - yoe / 100 + doy - 719468
    /// ```
    pub(crate) const fn from_civil(year: i64, month: u32, day: u32, seconds_of_day: i64) -> Self {
        let year = if month <= 2 { year - 1 } else { year };
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let shifted_month = (month as i64 + 9) % 12;
        let day_of_year = (153 * shifted_month + 2) / 5 + day as i64 - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        Self(days * SECONDS_PER_DAY + seconds_of_day)
    }

    /// The calendar year, month, day, and seconds of day of the instant.
    ///
    /// This is the inverse day count of the same paper.
    #[expect(
        clippy::cast_sign_loss,
        reason = "the algorithm yields a day in 1..=31 and a month in 1..=12"
    )]
    const fn to_civil(self) -> (i64, u32, u32, i64) {
        let days = self.0.div_euclid(SECONDS_PER_DAY) + 719_468;
        let seconds_of_day = self.0.rem_euclid(SECONDS_PER_DAY);
        let era = days.div_euclid(146_097);
        let day_of_era = days - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        } as u32;
        let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
        (year, month, day, seconds_of_day)
    }

    /// Reads a UTCTime or a GeneralizedTime, per RFC 5280, section 4.1.2.5.
    ///
    /// Both must be in UTC with seconds, as YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ.
    /// A two-digit year YY stands for 19YY when YY is 50 or more, else for 20YY.
    pub(crate) fn read(reader: &mut DerReader<'_>) -> Result<Self, DerError> {
        let (digits, year) = if reader.peek_tag() == Some(Tag::GENERALIZED_TIME) {
            let text = reader.element(Tag::GENERALIZED_TIME)?;
            let (year, rest) = text.split_first_chunk::<4>().ok_or(DerError::InvalidTime)?;
            (rest, Self::number(year)?)
        } else {
            let text = reader.element(Tag::UTC_TIME)?;
            let (year, rest) = text.split_first_chunk::<2>().ok_or(DerError::InvalidTime)?;
            let year = Self::number(year)?;
            (rest, if year >= 50 { 1900 + year } else { 2000 + year })
        };

        // Then MMDDHHMMSS and the Z of UTC.
        let Some((fields, b"Z")) = digits.split_first_chunk::<10>() else {
            return Err(DerError::InvalidTime);
        };
        let (fields, _) = fields.as_chunks::<2>();
        let [month, day, hour, minute, second] = fields else {
            return Err(DerError::InvalidTime);
        };
        let [month, day, hour, minute, second] =
            [month, day, hour, minute, second].map(|pair| Self::number(pair).unwrap_or(u32::MAX));
        if !(1..=12).contains(&month)
            || day == 0
            || day > Self::days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(DerError::InvalidTime);
        }
        let seconds_of_day = i64::from(hour * 3600 + minute * 60 + second);
        Ok(Self::from_civil(
            i64::from(year),
            month,
            day,
            seconds_of_day,
        ))
    }

    /// Writes the form RFC 5280 requires: UTCTime through 2049, GeneralizedTime from 2050.
    ///
    /// The instant must fall in the years 1950 to 9999.
    pub(crate) fn write(self, writer: &mut DerWriter) {
        let (year, month, day, seconds) = self.to_civil();
        let clock = format!(
            "{month:02}{day:02}{:02}{:02}{:02}Z",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        );
        if year < 2050 {
            let text = format!("{:02}{clock}", year % 100);
            writer.element(Tag::UTC_TIME, text.as_bytes());
        } else {
            let text = format!("{year:04}{clock}");
            writer.element(Tag::GENERALIZED_TIME, text.as_bytes());
        }
    }

    /// Decodes a run of ASCII decimal digits.
    fn number(digits: &[u8]) -> Result<u32, DerError> {
        digits.iter().try_fold(0_u32, |value, &digit| {
            if digit.is_ascii_digit() {
                Ok(value * 10 + u32::from(digit - b'0'))
            } else {
                Err(DerError::InvalidTime)
            }
        })
    }

    /// The days in a month of the proleptic Gregorian calendar.
    const fn days_in_month(year: u32, month: u32) -> u32 {
        match month {
            2 if year.is_multiple_of(4)
                && (!year.is_multiple_of(100) || year.is_multiple_of(400)) =>
            {
                29
            }
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Reads one time value from its encoding.
    fn read(bytes: &[u8]) -> Result<Timestamp, DerError> {
        Timestamp::read(&mut DerReader::new(bytes))
    }

    /// The encoding of a time with the tag and text.
    fn encode(tag: Tag, text: &str) -> Vec<u8> {
        let mut writer = DerWriter::new();
        writer.element(tag, text.as_bytes());
        writer.into_bytes()
    }

    #[test]
    fn known_instants() {
        // The epoch, and 2000-02-29 12:00:00, a leap day: 11016 days and 43200 seconds.
        assert_eq!(
            read(&encode(Tag::UTC_TIME, "700101000000Z")),
            Ok(Timestamp(0))
        );
        assert_eq!(
            read(&encode(Tag::UTC_TIME, "000229120000Z")),
            Ok(Timestamp(11_016 * 86_400 + 43_200))
        );

        // 1950 is the earliest two-digit year: 7305 days before the epoch.
        assert_eq!(
            read(&encode(Tag::UTC_TIME, "500101000000Z")),
            Ok(Timestamp(-7305 * 86_400))
        );

        // The libp2p test certificates span 1975-01-01 13:00 to 4096-01-01 13:00.
        assert_eq!(
            read(&encode(Tag::UTC_TIME, "750101130000Z")),
            Ok(Timestamp(157_813_200))
        );
        assert_eq!(
            read(&encode(Tag::GENERALIZED_TIME, "40960101130000Z")),
            Ok(Timestamp(67_090_165_200))
        );
    }

    #[test]
    fn malformed_times_are_refused() {
        // Mutation: a missing Z, fractional seconds, a local offset, and no seconds.
        for (tag, text) in [
            (Tag::UTC_TIME, "750101130000"),
            (Tag::GENERALIZED_TIME, "20200101130000.5Z"),
            (Tag::UTC_TIME, "7501011300+0100"),
            (Tag::UTC_TIME, "7501011300Z"),
        ] {
            assert_eq!(
                read(&encode(tag, text)),
                Err(DerError::InvalidTime),
                "{text}"
            );
        }

        // Mutation: 1900-02-29 is no date, nor are month 13, hour 24, or second 60.
        for text in [
            "19000229000000Z",
            "20201301000000Z",
            "20200101240000Z",
            "20200101000060Z",
            "2020010100000aZ",
        ] {
            assert_eq!(
                read(&encode(Tag::GENERALIZED_TIME, text)),
                Err(DerError::InvalidTime),
                "{text}"
            );
        }

        // 2000-02-29 exists: 2000 is a multiple of 400.
        assert!(read(&encode(Tag::GENERALIZED_TIME, "20000229000000Z")).is_ok());
    }

    #[test]
    fn writer_picks_the_rfc_5280_form() {
        // 2049-12-31 23:59:59 is the last UTCTime; one second later is GeneralizedTime.
        let last = Timestamp::from_civil(2049, 12, 31, 86_399);
        let mut writer = DerWriter::new();
        last.write(&mut writer);
        Timestamp(last.0 + 1).write(&mut writer);
        assert_eq!(
            writer.into_bytes(),
            [
                encode(Tag::UTC_TIME, "491231235959Z"),
                encode(Tag::GENERALIZED_TIME, "20500101000000Z")
            ]
            .concat()
        );
    }

    proptest! {
        #[test]
        fn written_times_read_back(seconds in -631_152_000_i64..253_402_300_800) {
            // Law: every instant from 1950 through 9999 survives writing and reading.
            let time = Timestamp(seconds);
            let mut writer = DerWriter::new();
            time.write(&mut writer);
            prop_assert_eq!(read(&writer.into_bytes()), Ok(time));
        }
    }
}
