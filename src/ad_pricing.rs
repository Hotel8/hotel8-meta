// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
// SPDX-License-Identifier: Apache-2.0

//! Pure meta ad pricing + discrepancy rules — DB-free.
//!
//! Mirrors `sync_ari` (multiplier + 2-dp formatting), the
//! `verify_rate_accuracy` discrepancy predicate, and re-exports the UTM
//! percent-encoding helper from `handlers`.

/// Apply a channel rate multiplier and format to 2 decimal places
/// (identical to `sync_ari`'s `format!("{:.2}", rate)`).
pub fn adjusted_rate(rate: f64, multiplier: f64) -> String {
    format!("{:.2}", rate * multiplier)
}

/// Why an ad row is discrepant vs the PMS inventory snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discrepancy {
    /// The PMS has no inventory row for this (room_type, date).
    MissingSource,
    /// Availability differs between the ad and the source.
    AvailabilityMismatch,
}

/// The `verify_rate_accuracy` predicate: a row is discrepant when the source
/// row is missing, or the ad's availability disagrees with the source.
pub fn discrepancy(source_available_rooms: Option<i64>, ad_available: bool) -> Option<Discrepancy> {
    match source_available_rooms {
        None => Some(Discrepancy::MissingSource),
        Some(av) => {
            if (av > 0) != ad_available {
                Some(Discrepancy::AvailabilityMismatch)
            } else {
                None
            }
        }
    }
}

/// Percent-encode a UTM parameter value (the `pct_encode` helper, moved
/// here so it is testable without the handler tree).
pub fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Build the metasearch deep-link URL with UTM attribution.
pub fn utm_deep_link(base_url: &str, utm_source: &str, utm_medium: &str, campaign: &str) -> String {
    format!(
        "{}?utm_source={}&utm_medium={}&utm_campaign={}",
        base_url,
        pct_encode(utm_source),
        pct_encode(utm_medium),
        pct_encode(campaign),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplier_and_formatting() {
        assert_eq!(adjusted_rate(100.0, 1.0), "100.00");
        assert_eq!(adjusted_rate(100.0, 1.15), "115.00");
        assert_eq!(adjusted_rate(99.995, 1.0), "100.00"); // {:.2} rounding
        assert_eq!(adjusted_rate(10.0, 0.0), "0.00");
    }

    #[test]
    fn discrepancy_predicate() {
        assert_eq!(discrepancy(None, true), Some(Discrepancy::MissingSource));
        assert_eq!(discrepancy(Some(0), true), Some(Discrepancy::AvailabilityMismatch));
        assert_eq!(discrepancy(Some(5), false), Some(Discrepancy::AvailabilityMismatch));
        assert_eq!(discrepancy(Some(5), true), None);
        assert_eq!(discrepancy(Some(0), false), None);
    }

    #[test]
    fn pct_encode_safe_chars() {
        assert_eq!(pct_encode("google-Hotel_2.test~x"), "google-Hotel_2.test~x");
        assert_eq!(pct_encode("a b&c"), "a%20b%26c");
        assert_eq!(pct_encode("100%"), "100%25");
    }

    #[test]
    fn utm_link_building() {
        let link = utm_deep_link("https://book.example", "google", "metasearch", "Summer 26");
        assert_eq!(
            link,
            "https://book.example?utm_source=google&utm_medium=metasearch&utm_campaign=Summer%2026"
        );
    }
}
