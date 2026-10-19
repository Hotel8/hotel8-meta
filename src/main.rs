// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Meta - metasearch channel management for Hotel8.
//!
//! Boot runs on the platform `sentin8-shell` crate (design
//! `sentin8/design/sentin8-sentin8-shell-technical-design.md`): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding,
//! middleware stack and PQ-TLS listener are owned by the shell. This binary
//! supplies only its registration data, state and routes. (Meta has no
//! OpenAPI spec - its registration carries none.)

mod ad_pricing;
mod admin_ui;
mod auth;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod event_consumer;
mod event_emit;
#[allow(dead_code)]
mod handlers;
mod master_key;
mod openapi;
pub mod policy;
mod registration;
#[allow(dead_code)]
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("hotel8:meta", "HOTEL8_META")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router)),
    )
    .await
}
