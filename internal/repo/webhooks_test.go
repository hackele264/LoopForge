package repo

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"agentflow/internal/domain"
)

func TestWebhookStorageKeepsSecretsOutOfAPIShape(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	w := domain.Webhook{ID: "wh-1", ProjectID: "p", WorkflowID: "wf", Name: "SIEM", Enabled: true, SecretHash: domain.HashWebhookSecret("s3cret"), SigningSecret: "hmac-key", SignatureHeader: "X-Sig", CreatedAt: now, UpdatedAt: now}
	if err := s.PutWebhook(w); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Webhook("wh-1")
	if !ok || got.SecretHash != w.SecretHash || got.SigningSecret != "hmac-key" || !got.HasSigningSecret {
		t.Fatalf("stored webhook = %+v", got)
	}
	list, err := s.WebhooksByProject("p", "")
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if other, _ := s.WebhooksByProject("p", "other"); len(other) != 0 {
		t.Fatalf("workflow filter leaked %v", other)
	}
	if err := s.DeleteWebhook("wh-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Webhook("wh-1"); ok {
		t.Fatal("webhook not deleted")
	}
}

func TestWebhookFingerprintClaimWindow(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	first, err := s.ClaimWebhookFingerprint("wh", "fp", time.Hour, now)
	if err != nil || !first.Claimed {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	if err := s.SetWebhookFingerprintRun("wh", "fp", "run-1"); err != nil {
		t.Fatal(err)
	}
	second, err := s.ClaimWebhookFingerprint("wh", "fp", time.Hour, now.Add(time.Minute))
	if err != nil || second.Claimed || second.RunID != "run-1" || second.Hits != 2 {
		t.Fatalf("second claim = %+v, %v", second, err)
	}
	other, _ := s.ClaimWebhookFingerprint("wh", "fp-other", time.Hour, now)
	if !other.Claimed {
		t.Fatal("a different fingerprint must claim its own run")
	}
	later, err := s.ClaimWebhookFingerprint("wh", "fp", time.Hour, now.Add(2*time.Hour))
	if err != nil || !later.Claimed || later.Hits != 1 {
		t.Fatalf("claim after the window = %+v, %v", later, err)
	}
	// A claim whose run never started is released so the next alert retries.
	if err := s.ReleaseWebhookFingerprint("wh", "fp"); err != nil {
		t.Fatal(err)
	}
	retry, _ := s.ClaimWebhookFingerprint("wh", "fp", time.Hour, now.Add(2*time.Hour))
	if !retry.Claimed {
		t.Fatal("released fingerprint must be claimable")
	}
	if n, err := s.PurgeExpiredWebhookFingerprints(now.Add(10 * time.Hour)); err != nil || n < 2 {
		t.Fatalf("purge removed %d, %v", n, err)
	}
}

func TestWebhookFingerprintClaimIsExclusive(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.ClaimWebhookFingerprint("wh", "same", time.Hour, now)
			if err != nil {
				t.Error(err)
				return
			}
			if c.Claimed {
				mu.Lock()
				claimed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if claimed != 1 {
		t.Fatalf("%d concurrent callers claimed the same fingerprint", claimed)
	}
}

func TestWebhookDeliveryLogIsBounded(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err := s.PutWebhook(domain.Webhook{ID: "wh", ProjectID: "p", WorkflowID: "wf", Name: "n", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < webhookDeliveryKeep+5; i++ {
		d := domain.WebhookDelivery{ID: fmt.Sprintf("d-%03d", i), WebhookID: "wh", ReceivedAt: now.Add(time.Duration(i) * time.Second), Status: domain.WebhookDeliveryRejected}
		if err := s.RecordWebhookDelivery(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordWebhookDelivery(domain.WebhookDelivery{ID: "d-last", WebhookID: "wh", ReceivedAt: now.Add(time.Hour), Status: domain.WebhookDeliveryStarted, RunID: "run-9"}); err != nil {
		t.Fatal(err)
	}
	all, err := s.WebhookDeliveries("wh", webhookDeliveryKeep)
	if err != nil || len(all) != webhookDeliveryKeep || all[0].ID != "d-last" {
		t.Fatalf("deliveries = %d (first %v), %v", len(all), all[0], err)
	}
	w, _ := s.Webhook("wh")
	if w.LastTriggeredAt == nil || !w.LastTriggeredAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("lastTriggeredAt = %v", w.LastTriggeredAt)
	}
}
