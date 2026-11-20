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
| `enabled` | A disabled webhook answers 409. |

Behind a reverse proxy the caller address is the proxy's. Set
`AGENTFLOW_WEBHOOK_TRUST_FORWARDED=true` to use the first `X-Forwarded-For`
hop instead; it is honoured only when the connection comes from a loopback
address, so only enable it when the proxy runs on the same host and
overwrites that header.

## Troubleshooting

调用记录 (or `GET /api/webhooks/{id}/deliveries`) lists the 50 most recent
calls with their outcome, HTTP status, run, fingerprint and source address.
Calls with an unknown ID or wrong secret are not logged against any webhook.
The last 200 deliveries per webhook are kept.

## Not covered yet

- No rate limiting per webhook; a flood of distinct alerts starts one run each.
- Duplicates join the case their fingerprint opened only with
  `caseMode: per_fingerprint`; otherwise they are counted on the first run.
  See [alerts and cases](cases.md).
- Expired fingerprints are cleared lazily when the same fingerprint returns;
  `PurgeExpiredWebhookFingerprints` exists but nothing schedules it yet.

## Storage

Tables `webhooks`, `webhook_dedup` and `webhook_deliveries` are created by
gorm's incremental AutoMigrate; `migrations/040_webhooks.sql` is the manual
equivalent. Storage behaviour on MySQL is covered by
`TestWebhookStorageOnMySQL`, run with `AGENTFLOW_WEBHOOK_TEST_DSN` pointing at
a disposable local MySQL.
