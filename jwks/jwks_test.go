package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func testJWKSServer(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     "test-kid",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	ks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)
	return ts, key
}

func TestFetcher_GetKey(t *testing.T) {
	ts, _ := testJWKSServer(t)

	f := NewFetcher(ts.URL, 0, nil)
	ctx := context.Background()

	keys, err := f.GetKey(ctx, "test-kid")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KeyID != "test-kid" {
		t.Errorf("expected kid test-kid, got %s", keys[0].KeyID)
	}
}

func TestFetcher_GetKey_NotFound(t *testing.T) {
	ts, _ := testJWKSServer(t)

	f := NewFetcher(ts.URL, 0, nil)
	ctx := context.Background()

	_, err := f.GetKey(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent kid")
	}
}

func TestFetcher_KeySet(t *testing.T) {
	ts, _ := testJWKSServer(t)

	f := NewFetcher(ts.URL, 0, nil)
	ctx := context.Background()

	// Before fetch, KeySet should be nil.
	if f.KeySet() != nil {
		t.Error("expected nil KeySet before fetch")
	}

	_, _ = f.GetKey(ctx, "test-kid")

	ks := f.KeySet()
	if ks == nil {
		t.Fatal("expected non-nil KeySet after fetch")
	}
	if len(ks.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(ks.Keys))
	}
}

func TestFetcher_Start(t *testing.T) {
	ts, _ := testJWKSServer(t)

	f := NewFetcher(ts.URL, 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f.Start(ctx)
	defer f.Stop()

	// After Start, keys should be available.
	ks := f.KeySet()
	if ks == nil {
		t.Fatal("expected keys after Start")
	}
}

func TestFetcher_Fetch_ReusesTenantHeader(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     "test-kid",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	ks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	var (
		mu      sync.Mutex
		headers []string
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		headers = append(headers, r.Header.Get("X-Tenant-ID"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)

	f := NewFetcher(ts.URL, 0, nil)
	if err := f.fetch(ContextWithTenantID(context.Background(), "tenant-1")); err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if err := f.fetch(context.Background()); err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(headers) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(headers))
	}
	if headers[0] != "tenant-1" {
		t.Fatalf("expected first request header tenant-1, got %q", headers[0])
	}
	if headers[1] != "tenant-1" {
		t.Fatalf("expected cached tenant header tenant-1, got %q", headers[1])
	}
}
