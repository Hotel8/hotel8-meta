# DESIGN.md: Hotel8:Meta — Detailed Design Document

## 1. Scope & Context

**Owned by Meta:** database `hotel8`, schema `meta` — 8 tables
(`meta.channels`, `channel_configs`, `channel_secrets`, `rate_ads`, `clicks`,
`sync_log` + `meta.channel_type` enum + `meta.outbox` /
`meta.audit_journal`); event family `meta`; the ARI-republish direct
consumer; RFW admin pages.

**NOT owned:** rate/inventory truth (hotel8:pms), distribution mechanics
(hotel8:distrib), auth decisions (Sentin8:Auth + Shield), payment capture.

### System context

```mermaid
graph TD
    subgraph "hotel8 vertical"
        M[hotel8:meta]
        P4[hotel8:pms] -- "hotel8:pms:inventory:updated (consumer group meta-ari-sync)" --> M
    end
    subgraph "platform"
        INGM[Sentin8:Proxy] -- "context headers" --> M
        BUSM[Sentin8:Bus] <-- "produce (M2M)" --> RM[shell relay]
        RM --- M
        CRYPTM[Sentin8:Crypto master key] -- "credential wrap" --> M
    end
    MS[Metasearch partners] -. "ad feeds / booking refs" .-> M
    DBM[(db hotel8 / schema meta)] --> M
```

### Container view

```mermaid
graph TD
    subgraph metad["hotel8:meta"]
        HM[/channels, configs, ads, content, sync/]
        ADSE[ad derivation + verification]
        SECRETS[credential custody]
        OUTM[(meta.outbox)]
        AJM[(meta.audit_journal)]
    end
    HM --> ADSE --> DBM2[(meta.* tables)]
    ADSE --> OUTM
```

## 2. Runtime Architecture

```mermaid
graph LR
    BOOTM[shell::serve] --> ENGM[Shield]
    BOOTM --> RPM[(pool cap 3)]
    BOOTM --> RLM[relay]
    BOOTM --> PJM[audit pusher]
    CONM[consumer: PMS inventory] -- SSE --> BUSM2[("stream meta intake")]
```

### Request lifecycle — save channel credentials

```mermaid
sequenceDiagram
    participant A as Hotel admin (Dash)
    participant M as hotel8:meta
    participant S as Shield
    participant K as crypto master key
    participant DB as db hotel8 (meta)
    A->>M: PUT /v1/channels/{id}/credentials
    M->>S: require(hotel8:meta:channels:write)
    S-->>M: permit
    M->>K: wrap secret material
    M->>DB: BEGIN, upsert channel + secret reference, journal, outbox (credentials:stored), COMMIT
    M-->>A: 200 (secret never echoed)
```

### Request lifecycle — rate ad verification

```mermaid
sequenceDiagram
    participant PMSm as hotel8:pms (event)
    participant M as hotel8:meta consumer
    participant DB as db hotel8 (meta)
    PMSm->>M: hotel8:pms:inventory:updated
    M->>DB: set_tenant_context
    M->>M: derive ad price (config adjustments over retail)
    alt rate verified
        M->>DB: INSERT meta.rate_ads (verified) + sync_log row
        M->>DB: outbox hotel8:meta:rate:verified / ari:synced
    else unverified
        M->>DB: sync_log records the miss (never advertise unverified)
    end
```

## 3. Data Model

```mermaid
erDiagram
    meta_channels ||--o{ meta_channel_configs : configures
    meta_channels ||--o{ meta_channel_secrets : "holds (by reference)"
    meta_channels ||--o{ meta_rate_ads : advertises
    meta_channels ||--o{ meta_clicks : attributes
    meta_channels ||--o{ meta_sync_log : logs
```

- `channel_type`: GOOGLE/TRIVAGO/KAYAK/SKYSCANNER/TRIPADVISOR/BING (enum).
- `channel_secrets`: secret-reference storage (wrapped by the platform
  master key), env-scoped FORCE-RLS.
- All tables env-scoped; audit journal included.

## 4. API Surface

**Public/admin** (`hotel8:meta:{read,write,channels:write}` + scope-mirror):

- Channels CRUD (`channel:configured/updated/deleted`).
- Channel configuration and credential storage
  (`credentials:stored`).
- Rate ads management and verification (`rate:verified`).
- Content push (`content:pushed`); full sync (`full_sync:completed`);
  partial sync (`ari:synced`; `ari:sync` trigger).
- Reservation-write hook for metasearch booking refs
  (`reservation:write`).
- Click/attribution listing; sync-log browsing.

**Admin/RFU**: RFW pages + shared policy admin trio.

### Cross-service data access — decision order (membus → bus → owner API)

Rate-ad freshness rides the bus: `hotel8:pms:inventory:updated` (consumer
group `meta-ari-sync`) re-derives rate ads from live availability — the
event carries the inventory snapshot, so re-derivation needs no PMS
call-back on the hot path. The owner-API residual is the daily ARI horizon
pull (`get_inventory` — synchronous read-your-writes for verification) and
reservation-write hook-backs from metasearch booking refs (the caller
returns the PMS confirmation). MemBus: none — ad refresh cadence is
content-sync pace. No pms-schema grant; meta's partner secrets stay in
meta.channel_secrets.

### Event flow

```mermaid
sequenceDiagram
    participant DB as meta.outbox
    participant R as shell relay
    participant B as Sentin8:Bus
    DB->>R: NOTIFY + poll
    R->>B: M2M produce
    alt ok
        B-->>R: 200 → relayed
    else down
        DB->>DB: attempts++ → DLQ at max
    end
```

## 5. Cross-Cutting Concerns

Auth/tenant/RLS/audit/drain/TLS/pool — platform contract via the shell.
Secret handling follows sentin8-secret-handling: references in tables,
plaintext only in-process via the master key.

## 6. Failure Modes & Recovery

```mermaid
flowchart TD
    A[Partner feed error] --> B[sync_log records outcome; retry path]
    C[Unverified rate] --> D[never advertised — sync row records the skip]
    E[Bus outage] --> F[outbox persists; relay retries]
    G[Master key unavailable] --> H[credential operations fail closed]
```

## 7. Concurrency & Performance Model

```mermaid
graph LR
    REQM --> MWM[middleware]
    MWM --> HM[handlers]
    HM --> CHM[("pool cap 3")]
    RLYM[relay] --> BM[("bus stream meta")]
```

- Read-mostly; the consumer republish is batched per channel from one PMS
  event.
- Clicks write append-only telemetry (no read-modify-write).

## 8. Invariants, Insecure-Defaults Rejected, Unsafe Rationale

- A published ad always carries a verified rate reference.
- Channel secrets are never stored plaintext, never logged, never returned
  by any read endpoint.
- Credential operations are fail-closed on key unavailability.
- No `unsafe`; no platform-DB access.
- Insecure defaults rejected: no shared tenant-wide credential; per-channel
  envelopes only.

## 9. Testing Strategy

```mermaid
graph TD
    UM[Unit — ad derivation + verification gates] --> IM[Integration — consumer wiring, policy parity]
    IM --> EM[E2E — admin surfaces + credential rotation via BFF]
```

## 10. Open Questions

- Bid-strategy automation.
- Programmatic content generation.

---

**Design attribution:** hotel8:meta and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
