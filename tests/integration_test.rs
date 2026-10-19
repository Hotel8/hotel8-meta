// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
// SPDX-License-Identifier: Apache-2.0

//! Hotel8:Meta integration tests (test-strategy Layer 3) - DB-free.
//!
//! Exercises the extracted ad pricing, discrepancy predicate and UTM link
//! builder exactly as `sync_ari` / `verify_rate_accuracy` / `generate_utm`
//! apply them.

use hotel8_meta_server::ad_pricing as ad;

#[test]
fn ari_multiplier_pipeline() {
    // sync_ari: rate × multiplier, formatted 2dp for the ad table.
    assert_eq!(ad::adjusted_rate(150.0, 1.0), "150.00");
    assert_eq!(ad::adjusted_rate(150.0, 1.15), "172.50");
    assert_eq!(ad::adjusted_rate(150.0, 0.85), "127.50");
    assert_eq!(ad::adjusted_rate(0.0, 1.3), "0.00");
}

#[test]
fn rate_accuracy_discrepancies() {
    use hotel8_meta_server::ad_pricing::Discrepancy::*;
    // verify_rate_accuracy: missing source OR availability mismatch.
    assert_eq!(ad::discrepancy(None, true), Some(MissingSource));
    assert_eq!(ad::discrepancy(Some(3), false), Some(AvailabilityMismatch));
    assert_eq!(ad::discrepancy(Some(0), true), Some(AvailabilityMismatch));
    assert_eq!(ad::discrepancy(Some(3), true), None);
    assert_eq!(ad::discrepancy(Some(0), false), None);
}

#[test]
fn utm_deep_link_matches_generate_utm_shape() {
    let link = ad::utm_deep_link("https://book.example.com", "google", "cpc", "SUMMER");
    assert_eq!(
        link,
        "https://book.example.com?utm_source=google&utm_medium=cpc&utm_campaign=SUMMER"
    );
}

#[test]
fn utm_encoding_is_safe_in_urls() {
    // Values with spaces / & / % must be percent-encoded.
    let link = ad::utm_deep_link("https://x.example", "a b", "c&d", "100%");
    assert!(link.contains("utm_source=a%20b"));
    assert!(link.contains("utm_medium=c%26d"));
    assert!(link.contains("utm_campaign=100%25"));
}

#[test]
fn multiplier_rounding_matches_display_format() {
    // `{:.2}` formatting (Rust rounds to nearest, ties to even on binary
    // floats) - the test pins the exact behavior `sync_ari` relies on.
    assert_eq!(ad::adjusted_rate(10.124, 1.0), "10.12");
    assert_eq!(ad::adjusted_rate(10.126, 1.0), "10.13");
    assert_eq!(ad::adjusted_rate(10.005, 1.0), "10.01"); // 10.005 stores as 10.0050000000000007816 → rounds up
}

#[test]
fn sold_out_rows_map_to_unavailable_ads() {
    // available_rooms = 0 → ad available = false (no discrepancy).
    assert_eq!(ad::discrepancy(Some(0), false), None);
}
