# Webhook triggers

A webhook starts one SOP when an external system (SIEM, EDR, mail gateway,
ticketing) calls its URL. The request body becomes the run's trigger payload,
readable from node conditions as `trigger` (see
[conditional workflows](conditional-workflows.md)).

## Creating one

In the flow designer open 流程设置 → Webhook 触发 and create a webhook for
the saved SOP, or call `POST /api/webhooks`. Runs execute as the user who
created the webhook, with that user's credentials, so create it with an
account that may run the SOP.

The response contains the full URL, `/api/hooks/{id}/{secret}`, exactly once.
Only a SHA-256 of the secret is stored; the UI shows its first characters so
rotated URLs can be told apart. Rotate the secret (轮换密钥 or
`POST /api/webhooks/{id}/rotate`) if it leaks; the old URL stops working at
once.

## Calling it

```bash
curl -X POST "https://loopforge.example.test/api/hooks/<id>/<secret>" \
  -H 'Content-Type: application/json' \
  -d '{"alert":{"title":"Phishing link clicked","rule":"PHISH-01","host":"pc-007","severity":"high"}}'
```

| Result | Status | Body |
|---|---|---|
| Run started | 202 | `{"status":"started","runId":"..."}` |
| Duplicate within the window | 200 | `{"status":"deduplicated","runId":"<first run>","hits":2}` |
| Unknown webhook or wrong secret | 401 | the same answer for both |
| Invalid signature | 401 | |
| Source address not allowed | 403 | |
| Method not allowed | 405 | |
| Webhook disabled | 409 | |
| Body over 1 MiB | 413 | |
| Rate limit spent | 429 | `{"status":"rate_limited","retryAfterSeconds":12}` plus a `Retry-After` header |
| Run could not start | 503 | |

- The body must be JSON; a value that is not an object is wrapped as
  `{"body": value}`. An empty body is `{}`.
- GET (when allowed) uses the query string as the payload; repeated keys
  become lists. PUT behaves like POST.
- The ingress needs no login even when `AGENTFLOW_AUTH_REQUIRED` is on; the
  URL secret is the credential. Access logs print the path with the secret
  replaced by `[redacted]`.

## Options

| Field | Effect |
|---|---|
| `titleField` | Dot path (`alert.title`, `items.0.name`) used as the run input; defaults to "Webhook 告警：<name>". |
| `dedupFields` | Dot paths forming the alert fingerprint. An alert whose fingerprint was seen within `dedupWindowSeconds` (default 3600, at most 7 days) starts no run; it is counted on the first run, which gets a `webhook.duplicate` event. An alert missing every field is never deduplicated. |
| `allowedCidrs` | Addresses or CIDR ranges allowed to call. |
| `methods` | Any of POST, PUT, GET; default POST only. |
| `signatureHeader` + `signingSecret` | Require an HMAC-SHA256 of the raw body, hex encoded, optionally prefixed with `sha256=` (the GitHub style). The signing secret is write-only. |
| `rateLimitPerMinute` + `rateLimitBurst` | Cap on new alerts (see below). 0 or absent is unlimited. |
| `enabled` | A disabled webhook answers 409. |

Behind a reverse proxy the caller address is the proxy's. Set
`AGENTFLOW_WEBHOOK_TRUST_FORWARDED=true` to use the first `X-Forwarded-For`
hop instead; it is honoured only when the connection comes from a loopback
address, so only enable it when the proxy runs on the same host and
overwrites that header.

## Rate limit

`rateLimitPerMinute` caps how many alerts per minute may start work (an
alert record, a case, a run); `rateLimitBurst` is how many may arrive at
once before that rate applies, and defaults to `rateLimitPerMinute`. An
alert over the limit answers 429 with `Retry-After` (whole seconds until the
next one is admitted), records nothing but a `rate_limited` delivery, and
can simply be sent again. Deduplication runs first: a duplicate absorbed by
an open fingerprint answers 200 and does not spend the budget. A refused
alert's fingerprint is released, so sending it again is not a duplicate of
nothing.

The budget is kept in the memory of each platform process: with several API
processes behind a load balancer each admits up to the limit, and a restart
starts with a full burst. Set the limit per process accordingly.

Pull alert sources admit through the same limit; a pass that hits it stops
and polls again after `Retry-After` (see
[pull alert sources](alert-sources.md#rate-limits)).

## Pulling instead of pushing

Products that cannot call a webhook (Splunk, CrowdStrike Falcon) can be
polled on a schedule; what a poll returns goes through the webhook exactly
like a pushed alert. See [pull alert sources](alert-sources.md).

## Troubleshooting

调用记录 (or `GET /api/webhooks/{id}/deliveries`) lists the 50 most recent
calls with their outcome, HTTP status, run, fingerprint and source address;
alerts a pull source admitted show the source (`sourceId`) instead.
Calls with an unknown ID or wrong secret are not logged against any webhook.
The last 200 deliveries per webhook are kept.

## Not covered yet

- The rate limit is per platform process, not shared across processes.
- Duplicates join the case their fingerprint opened only with
  `caseMode: per_fingerprint`; otherwise they are counted on the first run.
  See [alerts and cases](cases.md).
- Expired fingerprints are reclaimed when the same fingerprint returns, and
  every API process deletes the rest hourly.

## Storage

Tables `webhooks`, `webhook_dedup` and `webhook_deliveries` are created by
gorm's incremental AutoMigrate; `migrations/040_webhooks.sql` is the manual
equivalent. The rate limit fields are part of the stored JSON payload and
need no DDL (`migrations/046_phase6_backpressure.sql`). Storage behaviour on MySQL is covered by
`TestWebhookStorageOnMySQL`, run with `AGENTFLOW_WEBHOOK_TEST_DSN` pointing at
a disposable local MySQL.
