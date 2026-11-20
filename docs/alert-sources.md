# Pull alert sources

Some products cannot call a webhook: a Splunk notable index is read with a
search, CrowdStrike Falcon alerts with its Alerts API. A pull alert source
polls such a product on a schedule and admits what it returns through one of
the project's [webhooks](webhooks.md): the same title and severity mapping,
deduplication, case mode and SOP as a pushed alert.

Create one on a webhook card under the SOP's 流程设置 → 定时拉取, or with
`POST /api/alert-sources`.

## How a pass works

1. The source reads a time window `[since, until)`: from its checkpoint
   (where the last pass ended) to now minus `lagSeconds`, at most
   `windowSeconds` long.
2. It calls its connector action with its inputs rendered for that window.
   Inputs are templates over `window`:

   | Name | Value |
   |---|---|
   | `window.since`, `window.until` | Unix seconds |
   | `window.sinceMs`, `window.untilMs` | Unix milliseconds |
   | `window.sinceIso`, `window.untilIso` | RFC 3339 UTC |
   | `window.limit` | `pageLimit` |

3. It reads the list in the action output `itemsField` (default `items`).
   With `detailAction`, the listed values are IDs: they go to the detail
   action's list input `detailInput`, 100 at a time, and its `items` output
   holds the alerts.
4. Each alert is admitted once per source, keyed by the value at `idPath`
   (the whole alert when empty), through the webhook. A product that returns
   an alert again in a later window does not admit it twice.
5. The checkpoint moves to `until` and the next pass is due after
   `pollSeconds`.

When a pass returns `pageLimit` alerts there may be more in the window. With
`timePath` set the next pass starts from the last alert's time and runs at
once; without it the source moves on and reports a warning.

A failed pass (the product is down, credentials expired) keeps the
checkpoint, so the next pass reads the same window again. Retries back off
from `pollSeconds`, doubling to at most 10 minutes. A source whose webhook is
disabled does not call the product and reports why.

### Rate limits

When the webhook has a [rate limit](webhooks.md#rate-limit) and a pass
spends it, the pass stops at the first refused alert, which is logged as a
`rate_limited` delivery. Nothing is dropped: the refused and remaining
alerts are not marked as admitted, the checkpoint stays where the pass
started, and the next pass is due after the limit's `Retry-After` (at least
a second). That pass reads the same window again and admits only what was
not admitted yet. This is not a failure: the backoff does not grow and the
source shows a warning instead of an error.

The connector call itself follows the connection's own rate limit and
retries (see [connectors](connectors.md#rate-limits-and-retries)).

Only read-only actions (categories enrichment and utility) can list alerts:
a source runs unattended, so a response action is refused.

## Presets

The form fills these for the two products in the catalog.

**CrowdStrike Falcon** (Alerts API v2, needs `Alerts: Read`): action
`list_alert_ids` with

```
filter: created_timestamp:>='{{ window.sinceIso }}'+created_timestamp:<'{{ window.untilIso }}'
limit:  {{ window.limit }}
```

and an optional extra FQL clause ANDed with `+` (for example
`product:'epp'`), detail action `get_alerts` with input `ids`, `idPath:
composite_id`, `timePath: created_timestamp`, every 2 minutes. On the
webhook use title field `display_name`, severity field `severity_name` and
dedup field `composite_id`.

**Splunk** (a token with search rights; the connection's address is the
management port, for example `https://splunk.example.com:8089`): action
`search` with

```
search:   search index=notable | sort 0 _time
earliest: {{ window.since }}
latest:   {{ window.until }}
count:    {{ window.limit }}
```

`idPath: event_id`, `timePath: _time`, every minute. Notable events carry
`search_name` and `urgency` for the webhook's title and severity fields. A
management port with a self-signed certificate needs the certificate's
SHA-256 pinned on the connection (see [connectors](connectors.md#connections)).

Any other read-only action works through 自定义, which takes the fields as
JSON.

## Trying it

试拉取 (`POST /api/alert-sources/preview`) reads the most recent window for
the form's configuration and shows up to five alerts with the ID and title
each would get, without admitting anything. 立即拉取
(`POST /api/alert-sources/{id}/run`) polls a saved source at the next poller
tick.

Each source shows its last pass: when it ran, how many alerts it read and how
many were new, and the error or warning if any. Admitted alerts appear in the
webhook's 调用记录 with the source's name.

## Settings

| Field | Default | Range |
|---|---|---|
| `pollSeconds` | 60 | 30 – 86400 |
| `lagSeconds` | 60 | 0 – 3600: how far behind now a window ends, for products that index late |
| `windowSeconds` | 3600 | 60 – 86400: longest window one pass reads |
| `pageLimit` | 500 | 1 – 5000 |
| `lookbackSeconds` | 0 | 0 – 604800: where a new source starts, before its creation |

Changing a source keeps its checkpoint. Enabling a disabled source polls it
at once, from where it stopped.

## Running it

The poller runs in every process with the API role (`-role api` or `all`).
Several such processes share the work: each pass holds a lease on its source
in the database, so a source is polled by one process at a time; a lease held
by a process that died expires after 10 minutes. A process runs up to four
passes at once.

Admitted alert IDs are remembered for 30 days. Runs start as the webhook's
creator, like pushed alerts.

## Not covered yet

- No pagination cursor: one call per window, bounded by `pageLimit`, with
  `timePath` to resume a full page.
- No per-source rate limit beyond `pollSeconds`, the backoff, the webhook's
  alert limit and the connection's request limit.
- An alert dropped because it was larger than the trigger payload limit is
  logged and skipped.

## Storage

Tables `alert_sources` (configuration and poll state in separate columns, plus
the lease) and `alert_source_seen` (admitted alert IDs as SHA-256) are created
by gorm's incremental AutoMigrate; `migrations/044_alert_sources.sql` is the
manual equivalent.
