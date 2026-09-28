package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

func TestFetcher_Fetch_DoesNotLeakTenantAcrossCalls(t *testing.T) {
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

	// A first call carries an unverified tenant_id claim for "tenant-1".
	if err := f.fetch(ContextWithTenantID(context.Background(), "tenant-1")); err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	// A second, unrelated call on the SAME shared Fetcher carries no tenant
	// in its context at all. It must not inherit "tenant-1" from the first
	// call's unverified claim — the fetcher must not have persisted it.
	if err := f.fetch(context.Background()); err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	// A third call carries a different tenant; it must see its own value,
	// not anything left over from the first call.
	if err := f.fetch(ContextWithTenantID(context.Background(), "tenant-2")); err != nil {
		t.Fatalf("third fetch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(headers) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(headers))
	}
	if headers[0] != "tenant-1" {
		t.Fatalf("expected first request header tenant-1, got %q", headers[0])
	}
	if headers[1] != "" {
		t.Fatalf("expected no X-Tenant-ID header on second (tenant-less) request, got %q — tenant state leaked across calls", headers[1])
	}
	if headers[2] != "tenant-2" {
		t.Fatalf("expected third request header tenant-2, got %q", headers[2])
	}
}

// TestFetcher_Fetch_ConcurrentCallsDoNotShareTenantState exercises the same
// shared-Fetcher-across-callers scenario as
// TestFetcher_Fetch_DoesNotLeakTenantAcrossCalls but with genuinely
// concurrent, interleaved callers: half supply a distinct unverified
// tenant_id, half supply none. With the fetcher not persisting any
// cross-call tenant state, the set of tenant headers the server observes
// must exactly match what each goroutine actually sent — no goroutine may
// observe (or cause another to observe) a tenant it didn't provide itself.
// Run with -race to also catch any reintroduced mutable shared state.
func TestFetcher_Fetch_ConcurrentCallsDoNotShareTenantState(t *testing.T) {
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

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	expected := make(map[string]int, n)
	var expMu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var ctx context.Context
			var want string
			if i%2 == 0 {
				want = fmt.Sprintf("tenant-%d", i)
				ctx = ContextWithTenantID(context.Background(), want)
			} else {
				want = ""
				ctx = context.Background()
			}
			expMu.Lock()
			expected[want]++
			expMu.Unlock()
			if err := f.fetch(ctx); err != nil {
				errs <- fmt.Errorf("goroutine %d: fetch failed: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(headers) != n {
		t.Fatalf("expected %d requests, got %d", n, len(headers))
	}
	got := make(map[string]int, len(headers))
	for _, h := range headers {
		got[h]++
	}
	expMu.Lock()
	defer expMu.Unlock()
	for want, count := range expected {
		if got[want] != count {
			t.Errorf("tenant header %q: expected %d occurrences, got %d (headers=%v) — state leaked across concurrent calls", want, count, got[want], headers)
		}
	}
}
