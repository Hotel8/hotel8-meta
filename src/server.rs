// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Meta.
use crate::handlers::AppState;
use axum::routing::{get, post, put};
use std::sync::Arc;

/// Build the service state (config, pool, cert-presenting bus client). Runs
/// inside the shell's `with_state` closure - the pool arrives already
/// created and PG18-checked.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::MetaConfig::from_env();

    // Cert-presenting Bus client (CERTFREE-4V): the `meta` workload
    // CERTIFICATE is the identity - no DCR, no token (auth DESIGN
    // §4.3f); the mint retries while the fleet boots.
    let bus_client = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &config.sentin8_bus_url,
            &config.sentin8_auth_issuer,
            "meta",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "meta bus client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    // PMS cross-service client (CERTFREE-4V): this service presents its
    // own `meta` workload certificate - PMS's TLS layer authenticates
    // the handshake and the registry map authorizes the scopes (the
    // `pms:inventory:read` / `pms:rate-plans:read` / `pms:room-types:read`
    // grants ride the `meta` map row). The mint retries while the fleet
    // boots.
    let pms_client = loop {
        match hotel8::pms::client::H8pmsClient::with_workload_certificate(
            &config.pms_url,
            &config.sentin8_auth_issuer,
            "meta",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "meta pms client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    // ── Sentin8:Policy (Shield) ──
    // Load the service's policy sets; an unparsable policy text REFUSES TO
    // START (fail-closed at boot, design §3.3). Hot-reload consumes the
    // `policy` stream as a direct consumer (design §3.2); deny/would-deny
    // decisions emit to Stat (§4.2f). The engine is stored in AppState so
    // handlers gate via `policy::require` (step 5 is the ONLY gate).
    // ── Sentin8:Policy (Shield, shell-owned boot): consume the
    // engine the shell booted in step 8 - no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        config: Arc::new(config),
        pool: core.pool.clone(),
        bus_client,
        pms_client,
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "hotel8:meta".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine,
            auth_client: Arc::new(core.config.sentin8_auth_client.clone()),
        },
    };

    // Event-driven consumer - subscribes to the PMS stream family.
    crate::event_consumer::spawn(core.pool.clone(), state.bus_client.clone());
    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding and the standard middleware stack;
/// this adds ONLY routes (including the service's own `/v1/health`).
/// (Meta has no OpenAPI spec - its registration carries none.)
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(crate::handlers::health))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        // ── Sentin8:Policy admin API (shared implementation,
        // handlers generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<crate::handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<crate::handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<crate::handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<crate::handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<crate::handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<crate::handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<crate::handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<crate::handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<crate::handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<crate::handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<crate::handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<crate::handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<crate::handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<crate::handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<crate::handlers::AppState>),
        )
        .route(
            "/v1/channels",
            post(crate::handlers::create_channel).get(crate::handlers::list_channels),
        )
        .route(
            "/v1/channels/{channel_id}",
            put(crate::handlers::update_channel).delete(crate::handlers::delete_channel),
        )
        .route(
            "/v1/channel-configs",
            post(crate::handlers::configure_channel),
        )
        .route(
            "/v1/channels/{channel_id}/configs",
            get(crate::handlers::list_channel_configs),
        )
        .route(
            "/v1/channels/{channel_id}/sync",
            post(crate::handlers::sync_ari),
        )
        .route("/v1/cron/full-sync", post(crate::handlers::full_sync))
        .route(
            "/v1/channels/{channel_id}/verify",
            post(crate::handlers::verify_rate_accuracy),
        )
        .route(
            "/v1/channels/{channel_id}/content",
            post(crate::handlers::push_content),
        )
        .route(
            "/v1/admin/properties/{property_id}/analytics",
            get(crate::handlers::get_analytics),
        )
        .route("/v1/utm/generate", post(crate::handlers::generate_utm))
        .route(
            "/v1/channels/{channel_id}/credentials",
            post(crate::handlers::encrypt_credentials),
        )
        .route("/v1/rate-limits", get(crate::handlers::get_rate_limits))
}

/// Shared policy-admin surface accessor - the shared
/// handlers extract this service's admin state via `HasPolicyAdmin`.
impl sentin8::shield::admin::HasPolicyAdmin for crate::handlers::AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
