// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for hotel8-meta service.
//!
//! Schema groups mirror the contracts wire sections (channels, configs,
//! sync, verification, content, analytics, utm, credentials, rate limits).

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        sentin8::shell::policy_check_relation,
        sentin8::shell::policy_delete_attribute,
        sentin8::shell::policy_delete_relation,
        sentin8::shell::policy_delete_set,
        sentin8::shell::policy_get_set,
        sentin8::shell::policy_list_attributes,
        sentin8::shell::policy_list_relations,
        sentin8::shell::policy_list_sets,
        sentin8::shell::policy_mode_disable,
        sentin8::shell::policy_mode_enforce,
        sentin8::shell::policy_mode_shadow,
        sentin8::shell::policy_put_attribute,
        sentin8::shell::policy_put_relation,
        sentin8::shell::policy_put_set,
        sentin8::shell::policy_test_set,
        crate::handlers::health,
        crate::admin_ui::get_admin_ui,
        crate::handlers::create_channel,
        crate::handlers::list_channels,
        crate::handlers::update_channel,
        crate::handlers::delete_channel,
        crate::handlers::configure_channel,
        crate::handlers::list_channel_configs,
        crate::handlers::sync_ari,
        crate::handlers::full_sync,
        crate::handlers::verify_rate_accuracy,
        crate::handlers::push_content,
        crate::handlers::get_analytics,
        crate::handlers::generate_utm,
        crate::handlers::encrypt_credentials,
        crate::handlers::get_rate_limits,
    ),
    components(
        // ── Health
        schemas(hotel8::meta::contracts::MetaHealth),
        // ── Channels (alphabetical)
        schemas(
            hotel8::meta::contracts::ChannelCreateRequest,
            hotel8::meta::contracts::ChannelCreatedResponse,
            hotel8::meta::contracts::ChannelDeletedResponse,
            hotel8::meta::contracts::ChannelListQuery,
            hotel8::meta::contracts::ChannelListResponse,
            hotel8::meta::contracts::ChannelListRow,
            hotel8::meta::contracts::ChannelUpdateRequest,
            hotel8::meta::contracts::ChannelUpdatedResponse,
        ),
        // ── Channel configs (alphabetical)
        schemas(
            hotel8::meta::contracts::ChannelConfigListResponse,
            hotel8::meta::contracts::ChannelConfigRequest,
            hotel8::meta::contracts::ChannelConfigResponse,
        ),
        // ── ARI / full sync (alphabetical)
        schemas(
            hotel8::meta::contracts::AriSyncResult,
            hotel8::meta::contracts::ChannelSyncRow,
            hotel8::meta::contracts::FullSyncResult,
        ),
        // ── Rate verification (alphabetical)
        schemas(
            hotel8::meta::contracts::RateDiscrepancy,
            hotel8::meta::contracts::RateDiscrepancyMismatch,
            hotel8::meta::contracts::RateDiscrepancyMissing,
            hotel8::meta::contracts::RateVerificationResult,
        ),
        // ── Content push
        schemas(
            hotel8::meta::contracts::ContentPushResult,
            hotel8::meta::contracts::ContentRoomType,
        ),
        // ── Analytics (alphabetical)
        schemas(
            hotel8::meta::contracts::AnalyticsDailyRow,
            hotel8::meta::contracts::AnalyticsResponse,
            hotel8::meta::contracts::AnalyticsRevenue,
        ),
        // ── UTM deep links (alphabetical)
        schemas(
            hotel8::meta::contracts::UtmDeepLink,
            hotel8::meta::contracts::UtmGenerateRequest,
            hotel8::meta::contracts::UtmParams,
        ),
        // ── Credentials
        schemas(
            hotel8::meta::contracts::CredentialRequest,
            hotel8::meta::contracts::CredentialStored,
        ),
        // ── Rate limits (alphabetical)
        schemas(
            hotel8::meta::contracts::RateLimitAri,
            hotel8::meta::contracts::RateLimitFamily,
            hotel8::meta::contracts::RateLimits,
        ),
    ),
    security(),
    tags(
        (name = "policy", description = "Shield policy administration (shared surface)"),
        (name = "meta", description = "Hotel8:Meta - metasearch connector"),
    ),
)]
pub struct MetaOpenApi;
