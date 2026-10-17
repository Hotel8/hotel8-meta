# Hotel8:Meta — Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Hotel8:Meta **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

- Put the hotel's live rates in front of metasearch shoppers (Google Hotel
  Ads, Trivago, Kayak, Skyscanner, TripAdvisor, Bing) with correct content.
- Custody partner credentials safely (encrypted, by reference — never
  plaintext).
- Attribute metasearch clicks to bookings so acquisition spend is measurable.

## 2. Business Scope (What the Service Provides)

| Capability | Description |
|---|---|
| Channel registry | Metasearch channel configs with per-partner type |
| Credential custody | Encrypted, secret-reference storage per channel |
| Rate advertisement | Rates derived from PMS retail + adjustments, verified before publishing |
| Content push | Property content publication to partners |
| Rate verification | Ad-vs-inventory verification gate |
| Sync operations | Full and partial (ARI) syncs with a ledger |
| Click attribution | Click telemetry tied to booking references |
| Admin console | RFW pages incl. shared Shield policy admin |

**What the service does NOT own (business boundary)**

| Concern | Owning service |
|---|---|
| Rate and availability truth | hotel8:pms |
| Channel distribution logistics | hotel8:distrib |
| Reservation lifecycle | hotel8:pms |
| Identity & guest consent | Sentin8:Auth |
| Money movement | Bill8:Payments / Bill8:Ledger |
| Guest communication | Sentin8:Post |

## 3. Business Capabilities

| Area | Business rule |
|---|---|
| Channel setup | A metasearch channel operates only with stored credentials and an active configuration. |
| Rate ads | An advertised rate is always the verified derivation of the property's live retail rate plus the channel's configured adjustment. |
| Verification | Unverified rates are withheld from publication — parity incidents are prevented at the source. |
| Content | Property content publishes separately from rates so marketing changes don't disturb pricing. |
| Sync | Full syncs re-establish the complete catalog; partial (ARI) syncs propagate deltas; both are logged. |
| Attribution | Clicks are recorded with partner context so bookings can be traced to their source. |
| Secrets | Credential updates record the acting admin and never echo the secret. |

## 4. Business Events (Outbound)

| Event | Fires when |
|---|---|
| `hotel8:meta:channel:configured / updated / deleted` | Channel registry changes |
| `hotel8:meta:credentials:stored` | Credential rotation |
| `hotel8:meta:rate:verified` | An advertisement passed verification |
| `hotel8:meta:ari:sync / ari:synced` | Partial sync trigger/outcome |
| `hotel8:meta:full_sync:completed` | Full sync finished |
| `hotel8:meta:content:pushed` | Content publication |

**Inbound (consumed):** `hotel8:pms:inventory:updated` — re-derives and
verifies rate ads.

## 5. Business Rules & Invariants

1. No ad is published for an unverified rate.
2. Secrets exist only as encrypted references in the database — plaintext is
   never written or echoed.
3. Every credential change records the acting admin.
4. Click attribution rows are immutable telemetry.
5. A sync outcome is ledgered (success, partial, miss) — silent skips are an
   anomaly, not the norm.

## 6. Target-User Roles & Use Cases

| Persona | Use |
|---|---|
| Digital marketing manager | Configure metasearch channels, push ads/content |
| IT/security admin | Rotate partner credentials |
| Revenue manager | Check advertised rates vs live rates |
| Performance analyst | Click/booking attribution reports |
| Hotel admin | Policy admin for the surface |

## 7. KPIs / Success Criteria

- Ad rate parity with PMS zero-drift (verification holds).
- Sync completion within partner feed windows.
- Credential rotation completes without guest-visible impact.
- Attribution completeness: every metasearch booking traceable to a click.

## 8. Dependencies & Reliance on Other Services

| Reliance | For |
|---|---|
| hotel8:pms | Retail rates & availability (event-driven) |
| Sentin8:Auth + Shield | Identity; channel-scope authorization |
| Sentin8:Bus | `meta` stream + PMS intake |
| Sentin8:Crypto | Master key for credential wrapping |
| Sentin8:Sys | Audit ingestion |

## 9. Acceptance Criteria

1. A metasearch channel can be configured and verified with no code change.
2. Partner credentials rotate with zero downtime and zero plaintext
   exposure.
3. Every advertised rate is provably derived from the property's live rate.
4. A metasearch-referred booking is attributable to its click.
5. A full sync completes inside the maintenance window.

## 10. Open Business Questions

- Bid-strategy automation.
- Content template management.

---

**Design attribution:** hotel8:meta and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
