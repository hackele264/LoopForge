package repo

import (
	"testing"
	"time"

	"agentflow/internal/domain"
)

func TestConnectionsKeepSecretsOutOfLists(t *testing.T) {
	s, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	c := domain.Connection{ID: "cn-1", ProjectID: "sec", ConnectorID: "virustotal", Name: "vt", Params: map[string]string{"a": "b"}, Secrets: map[string]string{"api_key": "k1", "empty": ""}, CreatedAt: now, UpdatedAt: now}
	if err := s.PutConnection(c); err != nil {
		t.Fatal(err)
	}
	if err := s.PutConnection(domain.Connection{ID: "cn-2", ProjectID: "sec", ConnectorID: "shodan", Name: "s", CreatedAt: now.Add(time.Second), UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Connection("cn-1")
	if !ok || got.Secrets["api_key"] != "k1" || len(got.SecretsSet) != 1 || got.SecretsSet[0] != "api_key" || got.Params["a"] != "b" {
		t.Fatalf("connection = %+v", got)
	}
	list, err := s.Connections("sec", "")
	if err != nil || len(list) != 2 || list[0].Secrets != nil {
		t.Fatalf("list = %+v (%v)", list, err)
	}
	if only, _ := s.Connections("sec", "shodan"); len(only) != 1 || only[0].ID != "cn-2" {
		t.Fatalf("filtered = %+v", only)
	}
	if err := s.DeleteConnection("cn-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteConnection("cn-1"); err != ErrConnectionNotFound {
		t.Fatalf("second delete = %v", err)
	}
}
