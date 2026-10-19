// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
// SPDX-License-Identifier: Apache-2.0

//! Meta HTTP handlers - metasearch channel management.
use crate::config::MetaConfig;
use crate::event_emit::{emit_tx, Publisher};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use sentin8::auth::client::AuthContext;
use sqlx::Row;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<MetaConfig>,
    pub pool: sqlx::PgPool,
    pub bus_client: sentin8::bus::client::BusClient,
    /// Cross-service PMS client (B1) - replaces direct pms_* SQL.
    pub pms_client: hotel8::pms::client::H8pmsClient,
    /// Shield policy engine: step 5 is the ONLY gate -
    /// handlers verify the token (steps 1-4) then evaluate a
    /// `hotel8:meta:<resource>:<action>` target; no JWT scope check remains.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface - same engine
    /// instance the request path evaluates.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: uuid::Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(conn)
        .await;
}
fn resolve_env(auth: &AuthContext) -> uuid::Uuid {
    auth.env_id()
}
fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Map an outbox-emission failure to a 500 (DBX: a silently lost
/// event is a contract violation - same 500 contract as `err_db`).
fn err_emit(e: sentin8::bus::outbox::OutboxError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Percent-encoding for UTM parameters - delegated to the pure module
/// (`ad_pricing::pct_encode`, tested in D4).
fn pct_encode(s: &str) -> String {
    crate::ad_pricing::pct_encode(s)
}
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::MetaHealth),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "meta",
)]

pub async fn health(
    axum::extract::State(_state): axum::extract::State<AppState>,
) -> axum::Json<hotel8::meta::contracts::MetaHealth> {
    axum::Json(hotel8::meta::contracts::MetaHealth {
        status: "ok".into(),
        service: "meta".into(),
        version: sentin8::build_info::id(),
        build: sentin8::build_info::build_hash().to_string(),
    })
}

#[utoipa::path(
    post,
    path = "/v1/channels",
    request_body = hotel8::meta::contracts::ChannelCreateRequest,
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::ChannelCreatedResponse),
        (status = 400, description = "Missing property_id"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "meta",
)]
pub async fn create_channel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<hotel8::meta::contracts::ChannelCreateRequest>,
) -> Result<Json<hotel8::meta::contracts::ChannelCreatedResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    // Wire-compatible defaults mirroring the previous Value-based reads.
    let channel_code = req.channel_code.unwrap_or_default();
    let channel_name = req.channel_name.unwrap_or_default();
    let channel_type = req.channel_type.unwrap_or_else(|| "GOOGLE".to_string());
    let property_id = req.property_id;
    let row = sqlx::query("INSERT INTO meta.channels (property_id, env_id, channel_code, channel_name, channel_type) VALUES ($1, $2, $3, $4, $5) RETURNING id, channel_code, channel_name, channel_type::text as channel_type, is_active")
        .bind(property_id).bind(env_id).bind(channel_code).bind(channel_name).bind(channel_type)
        .fetch_one(&mut *conn).await.map_err(err_db)?;
    let id: uuid::Uuid = row.get("id");
    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        hotel8::meta::contracts::ChannelCreatedResponse {
            id,
            property_id,
            channel_code: row.get("channel_code"),
            channel_name: row.get("channel_name"),
            channel_type: row.get("channel_type"),
            is_active: row.get("is_active"),
        },
    ))
}
#[utoipa::path(
    get,
    path = "/v1/channels",
    params(
        ("property_id" = Option<uuid::Uuid>, Query, description = "Filter by property"),
    ),
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::ChannelListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "meta",
)]
pub async fn list_channels(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<hotel8::meta::contracts::ChannelListQuery>,
) -> Result<Json<hotel8::meta::contracts::ChannelListResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:read"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let property_id = params.property_id;
    let rows = if let Some(pid) = property_id {
        sqlx::query("SELECT id, channel_code, channel_name, channel_type::text as channel_type, is_active FROM meta.channels WHERE property_id = $1 ORDER BY channel_code").bind(pid).fetch_all(&mut *conn).await.map_err(err_db)?
    } else {
        sqlx::query("SELECT id, channel_code, channel_name, channel_type::text as channel_type, is_active FROM meta.channels ORDER BY channel_code").fetch_all(&mut *conn).await.map_err(err_db)?
    };
    let items: Vec<hotel8::meta::contracts::ChannelListRow> = rows
        .iter()
        .map(|r| hotel8::meta::contracts::ChannelListRow {
            id: r.get("id"),
            channel_code: r.get("channel_code"),
            channel_name: r.get("channel_name"),
            channel_type: r.get("channel_type"),
            is_active: r.get("is_active"),
        })
        .collect();
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::ChannelListResponse { items }))
}

// H4 - remaining handlers
#[utoipa::path(
    put,
    path = "/v1/channels/{channel_id}",
    request_body = hotel8::meta::contracts::ChannelUpdateRequest,
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::ChannelUpdatedResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Channel not found"),
    ),
    security(),
    tag = "meta",
)]
pub async fn update_channel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(channel_id): Path<uuid::Uuid>,
    Json(req): Json<hotel8::meta::contracts::ChannelUpdateRequest>,
) -> Result<Json<hotel8::meta::contracts::ChannelUpdatedResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let channel_name = req.channel_name;
    let is_active = req.is_active;
    let api_key_ref = req.api_key_ref;
    let row = sqlx::query(
        "UPDATE meta.channels SET \
         channel_name = COALESCE($1, channel_name), \
         is_active = COALESCE($2, is_active), \
         api_key_ref = COALESCE($3, api_key_ref) \
         WHERE id = $4 AND env_id = $5 \
         RETURNING id, channel_code, channel_name, channel_type::text as channel_type, is_active, api_key_ref",
    )
    .bind(channel_name).bind(is_active).bind(api_key_ref).bind(channel_id).bind(env_id)
    .fetch_optional(&mut *conn).await.map_err(err_db)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "channel not found".to_string()))?;
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:meta:channel:updated",
        serde_json::json!({ "channel_id": channel_id }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(err_emit)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::ChannelUpdatedResponse {
        id: row.get("id"),
        channel_code: row.get("channel_code"),
        channel_name: row.get("channel_name"),
        channel_type: row.get("channel_type"),
        is_active: row.get("is_active"),
        api_key_ref: row.get("api_key_ref"),
    }))
}
#[utoipa::path(
    delete,
    path = "/v1/channels/{channel_id}",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::ChannelDeletedResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Channel not found"),
    ),
    security(),
    tag = "meta",
)]
pub async fn delete_channel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(channel_id): Path<uuid::Uuid>,
) -> Result<Json<hotel8::meta::contracts::ChannelDeletedResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let res = sqlx::query("DELETE FROM meta.channels WHERE id = $1 AND env_id = $2")
        .bind(channel_id)
        .bind(env_id)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "channel not found".to_string()));
    }
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:meta:channel:deleted",
        serde_json::json!({ "channel_id": channel_id }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(err_emit)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::ChannelDeletedResponse {
        deleted: true,
        id: channel_id,
    }))
}
#[utoipa::path(
    post,
    path = "/v1/channel-configs",
    request_body = hotel8::meta::contracts::ChannelConfigRequest,
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::ChannelConfigResponse),
        (status = 400, description = "Missing channel_id or property_id"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "meta",
)]
pub async fn configure_channel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<hotel8::meta::contracts::ChannelConfigRequest>,
) -> Result<Json<hotel8::meta::contracts::ChannelConfigResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    // Wire-compatible defaults mirroring the previous Value-based reads.
    let channel_id = req.channel_id;
    let property_id = req.property_id;
    let hotel_id = req.hotel_id.unwrap_or_default();
    let rate_multiplier = req.rate_multiplier.unwrap_or(1.0);
    let landing_page_url = req.landing_page_url.unwrap_or_default();
    let utm_source = req.utm_source.unwrap_or_default();
    let utm_campaign = req.utm_campaign.unwrap_or_default();
    let is_enabled = req.is_enabled.unwrap_or(true);
    let row = sqlx::query(
        "INSERT INTO meta.channel_configs (channel_id, property_id, hotel_id, rate_multiplier, landing_page_url, utm_source, utm_campaign, is_enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (channel_id, property_id) DO UPDATE SET \
         hotel_id = EXCLUDED.hotel_id, rate_multiplier = EXCLUDED.rate_multiplier, \
         landing_page_url = EXCLUDED.landing_page_url, utm_source = EXCLUDED.utm_source, \
         utm_campaign = EXCLUDED.utm_campaign, is_enabled = EXCLUDED.is_enabled, updated_at = now() \
         RETURNING id, channel_id, property_id, hotel_id, rate_multiplier::text as rate_multiplier, landing_page_url, utm_source, utm_campaign, is_enabled",
    )
    .bind(channel_id).bind(property_id).bind(hotel_id).bind(rate_multiplier).bind(landing_page_url).bind(utm_source).bind(utm_campaign).bind(is_enabled)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:meta:channel:configured",
        serde_json::json!({ "channel_id": channel_id, "property_id": property_id }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(err_emit)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::ChannelConfigResponse {
        id: row.get("id"),
        channel_id: row.get("channel_id"),
        property_id: row.get("property_id"),
        hotel_id: row.get("hotel_id"),
        rate_multiplier: row.get("rate_multiplier"),
        landing_page_url: row.get("landing_page_url"),
        utm_source: row.get("utm_source"),
        utm_campaign: row.get("utm_campaign"),
        is_enabled: row.get("is_enabled"),
    }))
}
#[utoipa::path(
    get,
    path = "/v1/channels/{channel_id}/configs",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::ChannelConfigListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "meta",
)]
pub async fn list_channel_configs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(channel_id): Path<uuid::Uuid>,
) -> Result<Json<hotel8::meta::contracts::ChannelConfigListResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:read"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query(
        "SELECT id, channel_id, property_id, hotel_id, rate_multiplier::text as rate_multiplier, landing_page_url, utm_source, utm_campaign, is_enabled \
         FROM meta.channel_configs WHERE channel_id = $1 ORDER BY created_at",
    )
    .bind(channel_id).fetch_all(&mut *conn).await.map_err(err_db)?;
    let items: Vec<hotel8::meta::contracts::ChannelConfigResponse> = rows
        .iter()
        .map(|r| {
            hotel8::meta::contracts::ChannelConfigResponse {
                id: r.get("id"),
                channel_id: r.get("channel_id"),
                property_id: r.get("property_id"),
                hotel_id: r.get("hotel_id"),
                rate_multiplier: r.get("rate_multiplier"),
                landing_page_url: r.get("landing_page_url"),
                utm_source: r.get("utm_source"),
                utm_campaign: r.get("utm_campaign"),
                is_enabled: r.get("is_enabled"),
            }
        })
        .collect();
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::ChannelConfigListResponse { items }))
}
#[utoipa::path(
    post,
    path = "/v1/channels/{channel_id}/sync",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::AriSyncResult),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Channel not found"),
        (status = 502, description = "PMS inventory read failed"),
    ),
    security(),
    tag = "meta",
)]
pub async fn sync_ari(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(channel_id): Path<uuid::Uuid>,
) -> Result<Json<hotel8::meta::contracts::AriSyncResult>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;

    // Resolve channel + config
    let channel =
        sqlx::query("SELECT property_id FROM meta.channels WHERE id = $1 AND env_id = $2")
            .bind(channel_id)
            .bind(env_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "channel not found".to_string()))?;
    let property_id: uuid::Uuid = channel.get("property_id");
    let cfg = sqlx::query("SELECT rate_multiplier::text as rate_multiplier FROM meta.channel_configs WHERE channel_id = $1 AND property_id = $2 AND is_enabled = true")
        .bind(channel_id).bind(property_id)
        .fetch_optional(&mut *conn).await.map_err(err_db)?;
    let multiplier = cfg
        .as_ref()
        .and_then(|c| c.get::<String, _>("rate_multiplier").parse::<f64>().ok())
        .unwrap_or(1.0);

    // B1: inventory read goes through the PMS HTTP API. The API exposes
    // numeric availability + sell limits per room_type_id/date - rate codes
    // and amounts come from the property's rate plans via the same API.
    let today = chrono::Utc::now().date_naive();
    let horizon = today + chrono::Duration::days(90);
    let inv = state
        .pms_client
        .get_inventory(property_id, &today.to_string(), &horizon.to_string())
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("PMS inventory read failed: {e}"),
            )
        })?;
    let rows: Vec<serde_json::Value> = inv
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let property_currency = "USD"; // property currency source-of-truth wired in a follow-up story
    let mut pushed = 0i64;
    for r in &rows {
        let room_type_id = r.get("room_type_id").and_then(|v| v.as_str()).unwrap_or("");
        let date_s = r.get("date").and_then(|v| v.as_str()).unwrap_or("");
        let available_rooms = r
            .get("available_rooms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let sell_limit = r.get("sell_limit").and_then(|v| v.as_i64()).unwrap_or(0);
        // Meta requires per-room-type ad rows keyed by (channel, room_type_code,
        // rate_plan_code, date). Rate schedules are not part of the inventory
        // projection; the ad carries the adjusted sell price derived from the
        // channel multiplier (rate source wired to rate-plans in a follow-up).
        let date: sqlx::types::chrono::NaiveDate =
            chrono::NaiveDate::parse_from_str(date_s, "%Y-%m-%d").unwrap_or(today);
        let adj = crate::ad_pricing::adjusted_rate(sell_limit as f64, multiplier);
        let available = available_rooms > 0;
        let res = sqlx::query(
            "INSERT INTO meta.rate_ads (channel_id, property_id, room_type_code, rate_plan_code, date, rate_amount, currency_code, available) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (channel_id, property_id, room_type_code, rate_plan_code, date) DO UPDATE SET \
             rate_amount = EXCLUDED.rate_amount, currency_code = EXCLUDED.currency_code, available = EXCLUDED.available",
        )
        .bind(channel_id).bind(property_id).bind(room_type_id).bind("DEFAULT").bind(date).bind(&adj).bind(property_currency).bind(available)
        .execute(&mut *conn).await.map_err(err_db)?;
        pushed += res.rows_affected() as i64;
    }

    sqlx::query("INSERT INTO meta.sync_log (channel_id, property_id, sync_type, records_pushed, status) VALUES ($1, $2, 'ari', $3, 'ok')")
        .bind(channel_id).bind(property_id).bind(pushed).execute(&mut *conn).await.map_err(err_db)?;
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:meta:ari:synced",
        serde_json::json!({ "channel_id": channel_id, "records": pushed }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(err_emit)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::AriSyncResult {
        channel_id,
        property_id,
        records_pushed: pushed,
        rate_multiplier: multiplier,
    }))
}
#[utoipa::path(
    post,
    path = "/v1/cron/full-sync",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::FullSyncResult),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 502, description = "PMS inventory read failed"),
    ),
    security(),
    tag = "meta-cron",
)]
pub async fn full_sync(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<hotel8::meta::contracts::FullSyncResult>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;

    // All active channels
    let channels = sqlx::query(
        "SELECT id, property_id FROM meta.channels WHERE is_active = true AND env_id = $2",
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let mut total_pushed = 0i64;
    let mut channel_results: Vec<hotel8::meta::contracts::ChannelSyncRow> = Vec::new();

    for ch in &channels {
        let channel_id: uuid::Uuid = ch.get("id");
        let property_id: uuid::Uuid = ch.get("property_id");
        let cfg = sqlx::query("SELECT rate_multiplier::text as rate_multiplier FROM meta.channel_configs WHERE channel_id = $1 AND property_id = $2 AND is_enabled = true")
            .bind(channel_id).bind(property_id).fetch_optional(&mut *conn).await.map_err(err_db)?;
        let multiplier = cfg
            .as_ref()
            .and_then(|c| c.get::<String, _>("rate_multiplier").parse::<f64>().ok())
            .unwrap_or(1.0);

        // B1: inventory read via the PMS HTTP API (365-day horizon).
        let today = chrono::Utc::now().date_naive();
        let horizon = today + chrono::Duration::days(365);
        let inv = state
            .pms_client
            .get_inventory(property_id, &today.to_string(), &horizon.to_string())
            .await
            .map_err(|e| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("PMS inventory read failed: {e}"),
                )
            })?;
        let rows: Vec<serde_json::Value> = inv
            .get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let property_currency = "USD"; // property currency source-of-truth wired in a follow-up story
        let mut pushed = 0i64;
        for r in &rows {
            let room_type_id = r.get("room_type_id").and_then(|v| v.as_str()).unwrap_or("");
            let date_s = r.get("date").and_then(|v| v.as_str()).unwrap_or("");
            let available_rooms = r
                .get("available_rooms")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let sell_limit = r.get("sell_limit").and_then(|v| v.as_i64()).unwrap_or(0);
            let date: sqlx::types::chrono::NaiveDate =
                chrono::NaiveDate::parse_from_str(date_s, "%Y-%m-%d").unwrap_or(today);
            let adj = crate::ad_pricing::adjusted_rate(sell_limit as f64, multiplier);
            let available = available_rooms > 0;
            let res = sqlx::query(
                "INSERT INTO meta.rate_ads (channel_id, property_id, room_type_code, rate_plan_code, date, rate_amount, currency_code, available) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (channel_id, property_id, room_type_code, rate_plan_code, date) DO UPDATE SET \
                 rate_amount = EXCLUDED.rate_amount, currency_code = EXCLUDED.currency_code, available = EXCLUDED.available",
            )
            .bind(channel_id).bind(property_id).bind(room_type_id).bind("DEFAULT").bind(date).bind(&adj).bind(property_currency).bind(available)
            .execute(&mut *conn).await.map_err(err_db)?;
            pushed += res.rows_affected() as i64;
        }
        sqlx::query("INSERT INTO meta.sync_log (channel_id, property_id, sync_type, records_pushed, status) VALUES ($1, $2, 'full', $3, 'ok')")
            .bind(channel_id).bind(property_id).bind(pushed).execute(&mut *conn).await.map_err(err_db)?;
        total_pushed += pushed;
        channel_results.push(hotel8::meta::contracts::ChannelSyncRow {
            channel_id,
            property_id,
            records_pushed: pushed,
        });
    }
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:meta:full_sync:completed",
        serde_json::json!({ "channels": channels.len(), "records": total_pushed }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(err_emit)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::FullSyncResult {
        channels_synced: channels.len(),
        total_records_pushed: total_pushed,
        results: channel_results,
    }))
}
#[utoipa::path(
    post,
    path = "/v1/channels/{channel_id}/verify",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::RateVerificationResult),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Channel not found"),
        (status = 502, description = "PMS inventory read failed"),
    ),
    security(),
    tag = "meta",
)]
pub async fn verify_rate_accuracy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(channel_id): Path<uuid::Uuid>,
) -> Result<Json<hotel8::meta::contracts::RateVerificationResult>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;

    // B1: compare meta_rate_ads against the PMS via the HTTP API.
    // Load the property's current inventory snapshot and diff it in memory
    // (the old SQL joined pms_inventory directly - a §4.7 violation, and it
    // referenced non-existent columns).
    let channel =
        sqlx::query("SELECT property_id FROM meta.channels WHERE id = $1 AND env_id = $2")
            .bind(channel_id)
            .bind(env_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "channel not found".to_string()))?;
    let property_id: uuid::Uuid = channel.get("property_id");
    let today = chrono::Utc::now().date_naive();
    let horizon = today + chrono::Duration::days(90);
    let inv = state
        .pms_client
        .get_inventory(property_id, &today.to_string(), &horizon.to_string())
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("PMS inventory read failed: {e}"),
            )
        })?;
    // Snapshot: (room_type_id, date) -> (available_rooms)
    let mut src_map: std::collections::HashMap<(String, String), i64> =
        std::collections::HashMap::new();
    if let Some(items) = inv.get("items").and_then(|v| v.as_array()) {
        for it in items {
            let rt = it
                .get("room_type_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let d = it
                .get("date")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let avail = it
                .get("available_rooms")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            src_map.insert((rt, d), avail);
        }
    }
    let ads = sqlx::query(
        "SELECT room_type_code, rate_plan_code, date, rate_amount::text as ad_rate, currency_code, available \
         FROM meta.rate_ads WHERE channel_id = $1 ORDER BY date LIMIT 500",
    )
    .bind(channel_id).fetch_all(&mut *conn).await.map_err(err_db)?;
    let mut discrepancies: Vec<hotel8::meta::contracts::RateDiscrepancy> = Vec::new();
    for a in &ads {
        let rt: String = a.get("room_type_code");
        let date: sqlx::types::chrono::NaiveDate = a.get("date");
        let ad_available: bool = a.get("available");
        let src_avail = src_map.get(&(rt.clone(), date.to_string()));
        // D4: the discrepancy predicate lives in `ad_pricing::discrepancy`.
        match crate::ad_pricing::discrepancy(src_avail.copied(), ad_available) {
            Some(crate::ad_pricing::Discrepancy::MissingSource) => {
                discrepancies
                    .push(hotel8::meta::contracts::RateDiscrepancy::Missing(
                        hotel8::meta::contracts::RateDiscrepancyMissing {
                            room_type_code: rt.clone(),
                            rate_plan_code: a.get("rate_plan_code"),
                            date,
                            ad_rate: a.get("ad_rate"),
                            source_rate: None,
                            reason: "no_inventory_row".into(),
                        },
                    ));
            }
            Some(crate::ad_pricing::Discrepancy::AvailabilityMismatch) => {
                discrepancies
                    .push(hotel8::meta::contracts::RateDiscrepancy::Mismatch(
                        hotel8::meta::contracts::RateDiscrepancyMismatch {
                            room_type_code: rt.clone(),
                            rate_plan_code: a.get("rate_plan_code"),
                            date,
                            ad_rate: a.get("ad_rate"),
                            source_available: src_avail.copied(),
                            ad_available,
                            reason: "availability_mismatch".into(),
                        },
                    ));
            }
            None => {}
        }
    }
    let rows_len = discrepancies.len();
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:meta:rate:verified",
        serde_json::json!({ "channel_id": channel_id, "discrepancies": rows_len }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(err_emit)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::RateVerificationResult {
        channel_id,
        discrepancy_count: discrepancies.len(),
        discrepancies,
    }))
}
#[utoipa::path(
    post,
    path = "/v1/channels/{channel_id}/content",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::ContentPushResult),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Channel not found"),
        (status = 502, description = "PMS room-type read failed"),
    ),
    security(),
    tag = "meta",
)]
pub async fn push_content(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(channel_id): Path<uuid::Uuid>,
) -> Result<Json<hotel8::meta::contracts::ContentPushResult>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;

    let channel =
        sqlx::query("SELECT property_id FROM meta.channels WHERE id = $1 AND env_id = $2")
            .bind(channel_id)
            .bind(env_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "channel not found".to_string()))?;
    let property_id: uuid::Uuid = channel.get("property_id");

    // B1: room types via the PMS HTTP API.
    let room_types = state
        .pms_client
        .list_room_types(property_id)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("PMS room-type read failed: {e}"),
            )
        })?;
    let room_items: Vec<hotel8::meta::contracts::ContentRoomType> = room_types
        .iter()
        .map(|rt| hotel8::meta::contracts::ContentRoomType {
            room_type_code: rt
                .get("room_type_code")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            room_type_name: rt
                .get("room_type_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            description: rt
                .get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            max_occupancy: rt
                .get("max_occupancy")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
        })
        .collect();

    sqlx::query("INSERT INTO meta.sync_log (channel_id, property_id, sync_type, records_pushed, status) VALUES ($1, $2, 'content', $3, 'ok')")
        .bind(channel_id).bind(property_id).bind(room_items.len() as i64).execute(&mut *conn).await.map_err(err_db)?;
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:meta:content:pushed",
        serde_json::json!({ "channel_id": channel_id, "rooms": room_items.len() }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(err_emit)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::ContentPushResult {
        channel_id,
        property_id,
        room_types_pushed: room_items.len(),
        rooms: room_items,
    }))
}
#[utoipa::path(
    get,
    path = "/v1/admin/properties/{property_id}/analytics",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::AnalyticsResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "meta-admin",
)]
pub async fn get_analytics(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<hotel8::meta::contracts::AnalyticsResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:read"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;

    let row = sqlx::query(
        "SELECT \
         COUNT(*)::bigint as clicks, \
         COALESCE(SUM(cost_per_click), 0)::text as total_cost, \
         COUNT(DISTINCT c.channel_id)::bigint as channels \
         FROM meta.clicks c \
         WHERE c.property_id = $1 AND c.env_id = $2",
    )
    .bind(property_id)
    .bind(env_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    // Bookings / impressions aggregated from bus would require a join; approximate from clicks.
    let clicks: i64 = row.get("clicks");
    let total_cost: String = row.get("total_cost");
    let channels: i64 = row.get("channels");

    // Daily breakdown (last 30 days)
    let daily = sqlx::query(
        "SELECT click_date, COUNT(*)::bigint as clicks, COALESCE(SUM(cost_per_click), 0)::text as cost \
         FROM meta.clicks WHERE property_id = $1 AND env_id = $2 AND click_date >= CURRENT_DATE - INTERVAL '30 days' \
         GROUP BY click_date ORDER BY click_date",
    )
    .bind(property_id).bind(env_id).fetch_all(&mut *conn).await.map_err(err_db)?;
    let daily_items: Vec<hotel8::meta::contracts::AnalyticsDailyRow> = daily
        .iter()
        .map(|r| hotel8::meta::contracts::AnalyticsDailyRow {
            date: r.get("click_date"),
            clicks: r.get("clicks"),
            cost: r.get("cost"),
        })
        .collect();

    conn.commit().await.map_err(err_db)?;

    Ok(Json(hotel8::meta::contracts::AnalyticsResponse {
        property_id,
        clicks,
        total_cost: total_cost.clone(),
        channels,
        impressions: clicks, // proxied from clicks pending impressions table
        roi: hotel8::meta::contracts::AnalyticsRevenue {
            revenue: "0".into(),
            cost: total_cost,
        },
        daily: daily_items,
    }))
}
#[utoipa::path(
    post,
    path = "/v1/utm/generate",
    request_body = hotel8::meta::contracts::UtmGenerateRequest,
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::UtmDeepLink),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "meta",
)]
pub async fn generate_utm(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<hotel8::meta::contracts::UtmGenerateRequest>,
) -> Result<Json<hotel8::meta::contracts::UtmDeepLink>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:read"),
    )
    .await?;
    let _env_id = resolve_env(&a);

    // Wire-compatible defaults mirroring the previous Value-based reads.
    let base_url = req
        .base_url
        .unwrap_or_else(|| "https://book.example.com".into());
    let utm_source = req.utm_source.unwrap_or_else(|| "google".into());
    let utm_medium = req.utm_medium.unwrap_or_else(|| "cpc".into());
    let utm_campaign = req.utm_campaign.unwrap_or_default();
    let utm_term = req.utm_term.unwrap_or_default();
    let utm_content = req.utm_content.unwrap_or_default();
    let property_id = req.property_id.unwrap_or_default();
    let checkin = req.checkin.unwrap_or_default();
    let checkout = req.checkout.unwrap_or_default();

    let mut params: Vec<(String, String)> = vec![
        ("utm_source".into(), utm_source.clone()),
        ("utm_medium".into(), utm_medium.clone()),
        ("utm_campaign".into(), utm_campaign.clone()),
    ];
    if !utm_term.is_empty() {
        params.push(("utm_term".into(), utm_term.clone()));
    }
    if !utm_content.is_empty() {
        params.push(("utm_content".into(), utm_content.clone()));
    }
    if !property_id.is_empty() {
        params.push(("property_id".into(), property_id.into()));
    }
    if !checkin.is_empty() {
        params.push(("checkin".into(), checkin.into()));
    }
    if !checkout.is_empty() {
        params.push(("checkout".into(), checkout.into()));
    }

    // D4: the link shape (base + ?utm_source=&utm_medium=&utm_campaign=) is
    // `ad_pricing::utm_deep_link` - the multi-param path below extends it
    // with the optional term/content/property/dates parameters.
    let deep_link = crate::ad_pricing::utm_deep_link(
        &base_url,
        &utm_source,
        &utm_medium,
        &utm_campaign,
    );
    let extra_qs = params
        .iter()
        .skip(3)
        .map(|(k, v)| format!("{}={}", k, pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let deep_link = if extra_qs.is_empty() {
        deep_link
    } else {
        format!("{deep_link}&{extra_qs}")
    };

    Ok(Json(hotel8::meta::contracts::UtmDeepLink {
        deep_link,
        utm: hotel8::meta::contracts::UtmParams {
            source: utm_source,
            medium: utm_medium,
            campaign: utm_campaign,
            term: utm_term,
            content: utm_content,
        },
    }))
}
#[utoipa::path(
    post,
    path = "/v1/channels/{channel_id}/credentials",
    request_body = hotel8::meta::contracts::CredentialRequest,
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::CredentialStored),
        (status = 400, description = "Missing api_key"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Master key unavailable / seal failed"),
    ),
    security(),
    tag = "meta",
)]
pub async fn encrypt_credentials(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(channel_id): Path<uuid::Uuid>,
    Json(req): Json<hotel8::meta::contracts::CredentialRequest>,
) -> Result<Json<hotel8::meta::contracts::CredentialStored>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:admin"),
    )
    .await?;
    let env_id = resolve_env(&a);
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;

    let api_key = req.api_key;
    if api_key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "api_key required".to_string()));
    }
    let secret_ref = format!("hotel8://meta/channel/{}/api_key", channel_id);

    // B5 (principles §4.4, design §9): the plaintext NEVER lands in a table.
    // The value is envelope-encrypted with the platform master key
    // (SENTIN8_AUTH_MASTER_KEY; deterministic dev key in test mode) and only
    // the ciphertext is persisted in the service-owned secret table.
    let key = crate::master_key::require_master_key()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let envelope = sentin8::crypto::seal(&key, api_key.as_bytes()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("seal failed: {e}"),
        )
    })?;
    sqlx::query(
        "INSERT INTO meta.channel_secrets (env_id, channel_id, api_key_envelope) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (env_id, channel_id) DO UPDATE SET \
         api_key_envelope = EXCLUDED.api_key_envelope, updated_at = now()",
    )
    .bind(env_id)
    .bind(channel_id)
    .bind(&envelope)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    // The channel row keeps only a *reference* (store-by-reference).
    sqlx::query("UPDATE meta.channels SET api_key_ref = $1 WHERE id = $2 AND env_id = $3")
        .bind(&secret_ref)
        .bind(channel_id)
        .bind(env_id)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;

    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:meta:credentials:stored",
        serde_json::json!({ "channel_id": channel_id }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(err_emit)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(hotel8::meta::contracts::CredentialStored {
        channel_id,
        secret_ref,
        stored: true,
    }))
}
#[utoipa::path(
    get,
    path = "/v1/rate-limits",
    responses(
        (status = 200, description = "OK", body = hotel8::meta::contracts::RateLimits),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "meta",
)]
pub async fn get_rate_limits(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<hotel8::meta::contracts::RateLimits>, (StatusCode, String)> {
    let _a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:meta:read"),
    )
    .await?;
    use hotel8::meta::contracts::{RateLimitAri, RateLimitFamily, RateLimits};
    Ok(Json(RateLimits {
        sync: RateLimitFamily {
            max_concurrent: 4,
            rate_per_minute: 60,
            burst: 10,
        },
        content: RateLimitFamily {
            max_concurrent: 2,
            rate_per_minute: 20,
            burst: 5,
        },
        ari: RateLimitAri {
            batch_size: 365,
            interval_seconds: 60,
        },
    }))
}
