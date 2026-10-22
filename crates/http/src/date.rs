//! The date format of the date field.

use std::time::{SystemTime, UNIX_EPOCH};

/// Day names, indexed from Sunday.
const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Month names, indexed from January.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Formats a time as an IMF-fixdate, the form RFC 9110 section 5.6.7 requires.
///
/// ```text
///     Sun, 06 Nov 1994 08:49:37 GMT
/// ```
///
/// A time before 1970 is clamped to the epoch; no server clock reads that.
pub(crate) fn http_date(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let (days, second_of_day) = (seconds / 86_400, seconds % 86_400);

    // 1970-01-01 was a Thursday, index 4 from Sunday.
    let weekday = DAYS[((days + 4) % 7) as usize];
    let (year, month, day) = civil_from_days(days);

    format!(
        "{weekday}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        MONTHS[(month - 1) as usize],
        second_of_day / 3600,
        second_of_day / 60 % 60,
        second_of_day % 60,
    )
}

/// Converts days since 1970-01-01 to a Gregorian year, month, and day.
///
/// The algorithm is Howard Hinnant's, which counts in 400-year eras starting in March.
/// Starting the year in March puts the leap day last, so month lengths need no table.
///
/// ```text
///     era          400 years = 146097 days, the full Gregorian cycle
///     day of era   0 ..= 146096
///     year of era  0 ..= 399, from the 365-day years minus leap corrections
///     day of year  0 ..= 365, counted from March 1
///     month        (5 * doy + 2) / 153 maps March..February to 0..11
/// ```
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    // Shift the origin from 1970-01-01 to 0000-03-01, 719468 days earlier.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;

    // Remove the leap days of 4-, 100-, and 400-year cycles to count whole years.
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);

    // Months of 31, 30, 31, 30, 31 days repeat; 153 days per five months.
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };

    // January and February belong to the next calendar year.
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn known_dates() {
        // The epoch, the RFC's own example, and a leap day.
        let cases = [
            (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (784_111_777, "Sun, 06 Nov 1994 08:49:37 GMT"),
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (1_735_689_599, "Tue, 31 Dec 2024 23:59:59 GMT"),
        ];
        for (seconds, text) in cases {
            assert_eq!(http_date(UNIX_EPOCH + Duration::from_secs(seconds)), text);
        }
    }
}
