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
    paths(),
    components(schemas()),
    security(),
    tags(
        (name = "meta", description = "Hotel8:Meta — metasearch connector"),
    ),
)]
pub struct MetaOpenApi;