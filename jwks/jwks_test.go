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

// testKeySet builds a single-key JWKS for use as a test server's response
// body.
func testKeySet(t *testing.T) jose.JSONWebKeySet {
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
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
}

// testJWKSServer starts a JWKS server backed by a single test key. tenants,
// if non-nil, records the X-Tenant-ID header seen on every request in
// arrival order (safe for concurrent use).
func testJWKSServer(t *testing.T, tenants *tenantRecorder) *httptest.Server {
	t.Helper()
	ks := testKeySet(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tenants != nil {
			tenants.record(r.Header.Get("X-Tenant-ID"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// tenantRecorder collects X-Tenant-ID header values observed by a test
// server, safe for concurrent use by multiple in-flight requests.
type tenantRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *tenantRecorder) record(tenant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, tenant)
}

func (r *tenantRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.seen))
	copy(out, r.seen)
	return out
}

func TestFetcher_GetKey(t *testing.T) {
	ts := testJWKSServer(t, nil)

	f := NewFetcher(ts.URL, 0, nil, "")
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
	ts := testJWKSServer(t, nil)

	f := NewFetcher(ts.URL, 0, nil, "")
	ctx := context.Background()

	_, err := f.GetKey(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent kid")
	}
}

func TestFetcher_KeySet(t *testing.T) {
	ts := testJWKSServer(t, nil)

	f := NewFetcher(ts.URL, 0, nil, "")
	ctx := context.Background()

	// Before fetch, KeySet should be nil.
	if f.KeySet("") != nil {
		t.Error("expected nil KeySet before fetch")
	}

	_, _ = f.GetKey(ctx, "test-kid")

	ks := f.KeySet("")
	if ks == nil {
		t.Fatal("expected non-nil KeySet after fetch")
	}
	if len(ks.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(ks.Keys))
	}
}

func TestFetcher_Start(t *testing.T) {
	ts := testJWKSServer(t, nil)

	f := NewFetcher(ts.URL, 0, nil, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f.Start(ctx)
	defer f.Stop()

	// After Start, keys should be available.
	ks := f.KeySet("")
	if ks == nil {
		t.Fatal("expected keys after Start")
	}
}

// TestFetcher_Fetch_DoesNotLeakTenantAcrossCalls is a regression test for a
// tenant-claim leak: the Fetcher used to persist the unverified tenant_id
// claim from whichever call it validated most recently, and reused it as a
// fallback X-Tenant-ID header for later, unrelated calls sharing the same
// Fetcher instance. It proves that a call with no tenant in its context
// never inherits one from an earlier, unrelated call.
func TestFetcher_Fetch_DoesNotLeakTenantAcrossCalls(t *testing.T) {
	tenants := &tenantRecorder{}
	ts := testJWKSServer(t, tenants)
	f := NewFetcher(ts.URL, 0, nil, "")

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

	headers := tenants.all()
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

// TestFetcher_Fetch_UsesConfiguredTenantForCallsWithoutOne is a regression
// test for the fix to TestFetcher_Fetch_DoesNotLeakTenantAcrossCalls's
// original approach: removing the leaky per-request tenantID field also
// removed ANY tenant header from background-refresh fetches (Start's
// ticker calls fetch with the plain context passed to Start, which never
// carries a per-call tenant). Against a tenant-aware JWKS endpoint, sending
// no header there could resolve to a default/wrong tenant and silently
// populate the shared, tenant-unpartitioned key cache with the wrong keys.
//
// The fix is a static, operator-configured fallback (NewFetcher's
// configuredTenantID / validator.Config.TenantID) — NOT derived from any
// request, so it can't leak the way the old removed field did — used only
// when a fetch's ctx carries no per-call tenant. This proves: (a) a
// tenant-less call (simulating background refresh) uses the configured
// fallback, and (b) a call with its own per-call tenant still uses that,
// never the configured fallback.
func TestFetcher_Fetch_UsesConfiguredTenantForCallsWithoutOne(t *testing.T) {
	tenants := &tenantRecorder{}
	ts := testJWKSServer(t, tenants)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")

	// Simulates a background-refresh fetch: no per-call tenant in ctx.
	if err := f.fetch(context.Background()); err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	// A real, per-call request's tenant always wins over the configured
	// fallback.
	if err := f.fetch(ContextWithTenantID(context.Background(), "request-tenant")); err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	// Another tenant-less call again falls back to the configured tenant,
	// not whatever the previous per-call request happened to use.
	if err := f.fetch(context.Background()); err != nil {
		t.Fatalf("third fetch failed: %v", err)
	}

	headers := tenants.all()
	if len(headers) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(headers))
	}
	if headers[0] != "configured-tenant" {
		t.Fatalf("expected first (tenant-less) request to use configured fallback, got %q", headers[0])
	}
	if headers[1] != "request-tenant" {
		t.Fatalf("expected second request to use its own per-call tenant, got %q", headers[1])
	}
	if headers[2] != "configured-tenant" {
		t.Fatalf("expected third (tenant-less) request to use configured fallback again, not %q left over from the previous call", headers[2])
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
	tenants := &tenantRecorder{}
	ts := testJWKSServer(t, tenants)
	f := NewFetcher(ts.URL, 0, nil, "")

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

	headers := tenants.all()
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

// testPerTenantJWKSServer starts a JWKS server whose response depends on
// the X-Tenant-ID header of each request: it returns a single key whose kid
// is "kid-<tenant>" (or "kid-none" if the header is absent), all signing
// with the same underlying key pair. This lets tests distinguish which
// tenant's response actually ended up in a given cache slot.
func testPerTenantJWKSServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.Header.Get("X-Tenant-ID")
		kid := "kid-none"
		if tenant != "" {
			kid = "kid-" + tenant
		}
		jwk := jose.JSONWebKey{
			Key:       key.Public(),
			KeyID:     kid,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}
		ks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// TestFetcher_GetKey_PartitionsCacheByTenant is a regression test for a
// Copilot-review finding: the cache used to be a single, tenant-unpartitioned
// *jose.JSONWebKeySet field, so a background refresh (or any fetch) for one
// tenant could populate the one shared cache with that tenant's keys, and a
// later GetKey call for an unrelated tenant would return them on a kid
// match — cross-tenant key exposure. It proves tenant A's and tenant B's
// cached keys coexist (neither evicts the other) and a GetKey call scoped
// to one tenant never resolves a kid that was only ever fetched for the
// other tenant.
func TestFetcher_GetKey_PartitionsCacheByTenant(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")

	ctxA := ContextWithTenantID(context.Background(), "tenant-a")
	ctxB := ContextWithTenantID(context.Background(), "tenant-b")

	if _, err := f.GetKey(ctxA, "kid-tenant-a"); err != nil {
		t.Fatalf("GetKey for tenant A's own kid failed: %v", err)
	}
	if _, err := f.GetKey(ctxB, "kid-tenant-b"); err != nil {
		t.Fatalf("GetKey for tenant B's own kid failed: %v", err)
	}

	// Tenant A's context must never resolve tenant B's kid, and vice versa
	// — a cache hit under one tenant's slot must not satisfy a lookup
	// scoped to a different tenant.
	if _, err := f.GetKey(ctxA, "kid-tenant-b"); err == nil {
		t.Error("expected tenant A's context to NOT resolve tenant B's kid — cache is not tenant-partitioned")
	}
	if _, err := f.GetKey(ctxB, "kid-tenant-a"); err == nil {
		t.Error("expected tenant B's context to NOT resolve tenant A's kid — cache is not tenant-partitioned")
	}

	// Tenant A's own kid must still resolve afterward — proving the failed
	// cross-tenant lookups (and the refresh-on-miss they triggered) didn't
	// evict tenant A's legitimate cache entry.
	if _, err := f.GetKey(ctxA, "kid-tenant-a"); err != nil {
		t.Errorf("expected tenant A's own kid to still resolve after cross-tenant lookups, got: %v", err)
	}
	if _, err := f.GetKey(ctxB, "kid-tenant-b"); err != nil {
		t.Errorf("expected tenant B's own kid to still resolve after cross-tenant lookups, got: %v", err)
	}

	if ks := f.KeySet("tenant-a"); ks == nil || len(ks.Keys) != 1 || ks.Keys[0].KeyID != "kid-tenant-a" {
		t.Errorf("expected tenant-a's KeySet to hold exactly kid-tenant-a, got %+v", ks)
	}
	if ks := f.KeySet("tenant-b"); ks == nil || len(ks.Keys) != 1 || ks.Keys[0].KeyID != "kid-tenant-b" {
		t.Errorf("expected tenant-b's KeySet to hold exactly kid-tenant-b, got %+v", ks)
	}
}

// TestFetcher_Fetch_ConcurrentTenantsCoexistWithoutClobbering runs
// concurrent fetches for many distinct tenants on one shared Fetcher and
// proves every tenant's cache slot ends up holding exactly that tenant's
// own key — no concurrent write to the per-tenant cache map clobbers
// another tenant's entry. Run with -race to also catch any unsynchronized
// access to the map.
func TestFetcher_Fetch_ConcurrentTenantsCoexistWithoutClobbering(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tenant := fmt.Sprintf("tenant-%d", i)
			ctx := ContextWithTenantID(context.Background(), tenant)
			if err := f.fetch(ctx); err != nil {
				errs <- fmt.Errorf("tenant %s: fetch failed: %w", tenant, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	for i := 0; i < n; i++ {
		tenant := fmt.Sprintf("tenant-%d", i)
		ks := f.KeySet(tenant)
		if ks == nil || len(ks.Keys) != 1 {
			t.Fatalf("tenant %s: expected exactly 1 cached key, got %+v", tenant, ks)
		}
		wantKid := "kid-" + tenant
		if ks.Keys[0].KeyID != wantKid {
			t.Errorf("tenant %s: expected cached kid %q, got %q — cache entries clobbered each other", tenant, wantKid, ks.Keys[0].KeyID)
		}
	}
}
