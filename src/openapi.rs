// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:Meta
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for hotel8-meta service.
//!
//! Meta has no CLI-facing admin API endpoints, so the spec is empty.

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
    components(schemas()),
    security(),
    tags(
        (name = "policy", description = "Shield policy administration (shared surface)"),
        (name = "meta", description = "Hotel8:Meta - metasearch connector"),
    ),
)]pub struct MetaOpenApi;
