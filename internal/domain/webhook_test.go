package domain

import (
	"encoding/json"
	"net"
	"testing"
)

func decodeJSON(t *testing.T, raw string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestLookupJSONPath(t *testing.T) {
	v := decodeJSON(t, `{"a":{"b":[{"c":1},{"c":"two"}]},"x":null}`)
	cases := map[string]any{"a.b.0.c": 1.0, "a.b.1.c": "two", "a.b.2.c": nil, "a.missing": nil, "x.y": nil, "": nil, "a.b.-1": nil}
	for path, want := range cases {
		if got := LookupJSONPath(v, path); got != want {
			t.Errorf("%q = %v, want %v", path, got, want)
		}
	}
}

func TestWebhookFingerprint(t *testing.T) {
	fields := []string{"rule", "host"}
	a := WebhookFingerprint(decodeJSON(t, `{"rule":"R1","host":"pc","title":"x"}`), fields)
	b := WebhookFingerprint(decodeJSON(t, `{"title":"y","host":"pc","rule":"R1"}`), fields)
	c := WebhookFingerprint(decodeJSON(t, `{"rule":"R1","host":"pc2"}`), fields)
	if a == "" || a != b || a == c {
		t.Fatalf("fingerprints a=%s b=%s c=%s", a, b, c)
	}
	// Field order is part of the key; values may be objects.
	if WebhookFingerprint(decodeJSON(t, `{"rule":"R1","host":"pc"}`), []string{"host", "rule"}) == a {
		t.Fatal("field order must change the fingerprint")
	}
	if WebhookFingerprint(decodeJSON(t, `{"other":1}`), fields) != "" || WebhookFingerprint(decodeJSON(t, `{"rule":"R1"}`), nil) != "" {
		t.Fatal("no fields or no values must not fingerprint")
	}
}

func TestWebhookTitleAndChecks(t *testing.T) {
	w := Webhook{Name: "SIEM", TitleField: "alert.title"}
	if got := WebhookTitle(w, decodeJSON(t, `{"alert":{"title":"  Bad login  "}}`)); got != "Bad login" {
		t.Fatalf("title = %q", got)
	}
	if got := WebhookTitle(w, decodeJSON(t, `{}`)); got != "Webhook 告警：SIEM" {
		t.Fatalf("fallback title = %q", got)
	}
	if got := WebhookTitle(Webhook{TitleField: "n"}, decodeJSON(t, `{"n":{"k":1}}`)); got != `{"k":1}` {
		t.Fatalf("object title = %q", got)
	}
	w = Webhook{AllowedCIDRs: []string{"10.0.0.0/8", "2001:db8::1"}}
	for ip, want := range map[string]bool{"10.9.8.7": true, "11.0.0.1": false, "2001:db8::1": true, "2001:db8::2": false} {
		if got := w.AllowsIP(net.ParseIP(ip)); got != want {
			t.Errorf("AllowsIP(%s) = %v", ip, got)
		}
	}
	if w.AllowsIP(nil) || !(Webhook{}).AllowsIP(nil) {
		t.Fatal("nil address: refused with an allowlist, allowed without")
	}
	if !(Webhook{}).AllowsMethod("POST") || (Webhook{}).AllowsMethod("GET") || !(Webhook{Methods: []string{"GET"}}).AllowsMethod("get") {
		t.Fatal("method rules")
	}
}
