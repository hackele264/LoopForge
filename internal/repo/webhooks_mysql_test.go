package repo

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"agentflow/internal/domain"
)

// TestWebhookStorageOnMySQL covers what SQLite cannot: row locks between
// connections and MySQL's SQL dialect. It runs only against a disposable
// local Docker MySQL named by AGENTFLOW_WEBHOOK_TEST_DSN.
func TestWebhookStorageOnMySQL(t *testing.T) {
	dsn := os.Getenv("AGENTFLOW_WEBHOOK_TEST_DSN")
	if dsn == "" {
		t.Skip("disposable local Docker MySQL only")
	}
	s, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := fmt.Sprintf("wh-mysql-test-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.PutWebhook(domain.Webhook{ID: id, ProjectID: "mysql-test", WorkflowID: "wf", Name: "n", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	defer s.DeleteWebhook(id)

	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed, hits := 0, 0
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.ClaimWebhookFingerprint(id, "fp", time.Hour, now)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if c.Claimed {
				claimed++
			} else if c.Hits > hits {
				hits = c.Hits
			}
		}()
	}
	wg.Wait()
	if claimed != 1 || hits != 30 {
		t.Fatalf("claimed %d, highest hit %d; want exactly one claim and 30 hits", claimed, hits)
	}
	later, err := s.ClaimWebhookFingerprint(id, "fp", time.Hour, now.Add(2*time.Hour))
	if err != nil || !later.Claimed {
		t.Fatalf("expired fingerprint not reclaimed: %+v, %v", later, err)
	}

	for i := 0; i < webhookDeliveryKeep+3; i++ {
		d := domain.WebhookDelivery{ID: fmt.Sprintf("%s-d%03d", id, i), WebhookID: id, ReceivedAt: now.Add(time.Duration(i) * time.Second), Status: domain.WebhookDeliveryStarted}
		if err := s.RecordWebhookDelivery(d); err != nil {
			t.Fatalf("record delivery %d: %v", i, err)
		}
	}
	list, err := s.WebhookDeliveries(id, webhookDeliveryKeep)
	if err != nil || len(list) != webhookDeliveryKeep {
		t.Fatalf("deliveries = %d, %v", len(list), err)
	}
	if w, _ := s.Webhook(id); w.LastTriggeredAt == nil {
		t.Fatal("lastTriggeredAt not stamped")
	}
}
