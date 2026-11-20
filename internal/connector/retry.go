package connector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"agentflow/internal/domain"
	"agentflow/internal/ratelimit"
)

const (
	// retryBaseDelay is the first backoff; each retry doubles it.
	retryBaseDelay = 500 * time.Millisecond
	// retryMaxBackoff caps a computed backoff.
	retryMaxBackoff = 30 * time.Second
	// retryMaxWait caps any wait, including a vendor's Retry-After.
	retryMaxWait = 60 * time.Second
)

// connectionLimits holds the per-connection request buckets. It is shared
// by every executor in the process (the engine's, the connection test's and
// the alert source poller's), so the limit applies per platform process.
var connectionLimits = ratelimit.NewRegistry()

// httpResult is one response, read to the size bound.
type httpResult struct {
	status    int
	header    http.Header
	body      []byte
	truncated bool
}

// retryRecord is one attempt that was retried.
type retryRecord struct {
	attempt int
	status  int
	err     string
	wait    time.Duration
}

func (x *Executor) limits() *ratelimit.Registry {
	if x.limitReg != nil {
		return x.limitReg
	}
	return connectionLimits
}

// send performs the request, waiting for the connection's rate limit before
// each attempt and retrying on 429 (any method: the vendor did not process
// the request) and, for GET and HEAD only, on 5xx and transport errors, so a
// response action is never sent twice after the vendor may have acted on it.
// Waits follow Retry-After when the vendor sends one, otherwise exponential
// backoff with jitter, capped at one minute. timeout bounds each attempt;
// ctx bounds the whole call including waits. The returned result is the last
// response; err is the last transport error.
func (x *Executor) send(ctx context.Context, client *http.Client, conn *domain.Connection, method, target string, headers http.Header, body []byte, timeout time.Duration, success []int, secrets []string) (httpResult, []retryRecord, error) {
	retries := conn.Retries()
	bucket := x.limits().Bucket(conn.ID, conn.RateLimitPerSecond, conn.RateLimitBurst)
	var records []retryRecord
	for attempt := 1; ; attempt++ {
		if bucket != nil {
			if err := bucket.Wait(ctx); err != nil {
				return httpResult{}, records, fmt.Errorf("等待连接限流时中止：%w", err)
			}
		}
		res, err := x.attempt(ctx, client, method, target, headers, body, timeout)
		rec := retryRecord{attempt: attempt}
		retryable := false
		var hint time.Duration
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return res, records, err
			}
			retryable = idempotentMethod(method)
			rec.err = redact(err.Error(), secrets)
		case accepted(success, res.status):
			return res, records, nil
		case res.status == http.StatusTooManyRequests:
			retryable = true
			hint = parseRetryAfter(res.header.Get("Retry-After"), time.Now())
			rec.status = res.status
		case res.status >= 500:
			retryable = idempotentMethod(method)
			hint = parseRetryAfter(res.header.Get("Retry-After"), time.Now())
			rec.status = res.status
		}
		if !retryable || attempt > retries {
			return res, records, err
		}
		wait := hint
		if wait <= 0 {
			wait = x.backoff(attempt)
		}
		if maxWait := x.maxWait(); wait > maxWait {
			wait = maxWait
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < wait {
			// Waiting would outlast the caller; report the failure now.
			return res, records, err
		}
		rec.wait = wait
		records = append(records, rec)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return res, records, err
		case <-timer.C:
		}
	}
}

// attempt sends the request once and reads the response.
func (x *Executor) attempt(ctx context.Context, client *http.Client, method, target string, headers http.Header, body []byte, timeout time.Duration) (httpResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return httpResult{}, err
	}
	req.Header = headers.Clone()
	resp, err := client.Do(req)
	if err != nil {
		return httpResult{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return httpResult{}, fmt.Errorf("读取响应失败：%w", err)
	}
	res := httpResult{status: resp.StatusCode, header: resp.Header, body: raw}
	if len(raw) > maxResponseBytes {
		res.body, res.truncated = raw[:maxResponseBytes], true
	}
	return res, nil
}

func idempotentMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func (x *Executor) backoff(attempt int) time.Duration {
	base := x.retryBase
	if base <= 0 {
		base = retryBaseDelay
	}
	d := base
	for i := 1; i < attempt && d < retryMaxBackoff; i++ {
		d *= 2
	}
	if d > retryMaxBackoff {
		d = retryMaxBackoff
	}
	// Jitter in [d/2, d] so callers that failed together spread out.
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func (x *Executor) maxWait() time.Duration {
	if x.retryMaxWait > 0 {
		return x.retryMaxWait
	}
	return retryMaxWait
}

// parseRetryAfter reads a Retry-After header in seconds or as an HTTP date;
// zero means absent or unreadable.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(value, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		if secs > int64(retryMaxWait/time.Second) {
			return retryMaxWait
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		if d := at.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// retryLog is the retries as the action output shows them.
func retryLog(records []retryRecord) []any {
	out := make([]any, 0, len(records))
	for _, r := range records {
		entry := map[string]any{"attempt": float64(r.attempt), "waitMs": float64(r.wait.Milliseconds())}
		if r.status != 0 {
			entry["status"] = float64(r.status)
		}
		if r.err != "" {
			entry["error"] = r.err
		}
		out = append(out, entry)
	}
	return out
}

func retriedNote(records []retryRecord) string {
	if len(records) == 0 {
		return ""
	}
	return fmt.Sprintf("（重试 %d 次）", len(records))
}
