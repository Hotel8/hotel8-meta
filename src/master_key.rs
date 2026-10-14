// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
// SPDX-License-Identifier: Apache-2.0

//! Master-key loading for envelope-encrypted secrets.
//!
//! Mirrors the fail-closed rule of `sentin8/services/auth/src/jwks.rs` §2.4:
//! without `SENTIN8_AUTH_MASTER_KEY` the service refuses to persist or read
//! secret material — unless `SENTIN8_AUTH_DEV_INSECURE_KEY` is set (CI /
//! integration tests only), in which case a deterministic dev key is used
//! with a loud warning.

/// Load the AES-256-GCM master key from `SENTIN8_AUTH_MASTER_KEY`.
/// Returns `None` when unset — callers decide fail-closed behavior.
pub fn master_key() -> Option<sentin8::crypto::MasterKey> {
    sentin8::crypto::MasterKey::from_base64(
        &std::env::var("SENTIN8_AUTH_MASTER_KEY").unwrap_or_default(),
    )
    .ok()
    .flatten()
}

/// The master key to use, or a deterministic dev key in test mode.
///
/// Fail-closed: without `SENTIN8_AUTH_MASTER_KEY` the service refuses to
/// handle secret material unless `SENTIN8_AUTH_DEV_INSECURE_KEY` is set.
pub fn require_master_key() -> Result<sentin8::crypto::MasterKey, String> {
    if let Some(k) = master_key() {
        return Ok(k);
    }
    if std::env::var("SENTIN8_AUTH_DEV_INSECURE_KEY").is_ok() {
        tracing::warn!(
            "SENTIN8_AUTH_MASTER_KEY is not set — using a DETERMINISTIC DEV KEY. \
             Never run production this way (set SENTIN8_AUTH_DEV_INSECURE_KEY only in tests)."
        );
        return Ok(sentin8::crypto::derive_key(b"hotel8-meta-dev-insecure-key"));
    }
    Err(
        "SENTIN8_AUTH_MASTER_KEY is not set (base64, 32 bytes) — refusing to \
         handle channel credential material. Generate one with: openssl rand -base64 32"
            .to_string(),
    )
}
