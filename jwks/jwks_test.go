package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	// This test issues two fetches for "configured-tenant" back to back;
	// disable the unrelated minFetchInterval cooldown (see
	// TestFetcher_Fetch_ThrottlesRepeatedFetchesRegardlessOfExemption)
	// so it isn't what's being exercised here.
	f.minFetchInterval = 0

	// Simulates Start's internal background-refresh call: no per-call
	// tenant in ctx, but explicitly marked as the internal refresh path
	// (see internalRefreshContext) — an ordinary tenantless request
	// context would NOT resolve to the configured tenant; see
	// TestFetcher_GetKey_TenantlessRequestNeverUsesConfiguredTenant.
	if err := f.fetch(internalRefreshContext(context.Background())); err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	// A real, per-call request's tenant always wins over the configured
	// fallback.
	if err := f.fetch(ContextWithTenantID(context.Background(), "request-tenant")); err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	// Another internal-refresh call again falls back to the configured
	// tenant, not whatever the previous per-call request happened to use.
	if err := f.fetch(internalRefreshContext(context.Background())); err != nil {
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
	// Half these goroutines share the SAME resolved tenant ("") and are
	// expected to all succeed — this test is about tenant leakage, not
	// the separate minFetchInterval cooldown (see
	// TestFetcher_Fetch_ThrottlesRepeatedFetchesRegardlessOfExemption).
	f.minFetchInterval = 0

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	expectedTenants := make(map[string]bool, n) // set of tenants SOME goroutine legitimately used
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
			expectedTenants[want] = true
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

	// The 10 goroutines sharing the SAME resolved tenant ("") may now be
	// coalesced by fetch's in-flight deduplication (see
	// Fetcher.inFlightFetches) into fewer than 10 actual network requests
	// for "" — that's the point of coalescing, not a leak — so an exact
	// total request count can no longer be asserted. What still proves
	// "no leakage" is: every observed header is a tenant some goroutine
	// actually used (never a value nobody requested), and each of the 10
	// distinct explicit tenants (never shared with another goroutine, so
	// never coalesced) appears exactly once.
	headers := tenants.all()
	if len(headers) == 0 {
		t.Fatal("expected at least 1 request")
	}
	got := make(map[string]int, len(headers))
	for _, h := range headers {
		got[h]++
	}
	expMu.Lock()
	for h := range got {
		if !expectedTenants[h] {
			t.Errorf("observed header %q that no goroutine actually requested (headers=%v) — state leaked across concurrent calls", h, headers)
		}
	}
	expMu.Unlock()
	for i := 0; i < n; i += 2 {
		want := fmt.Sprintf("tenant-%d", i)
		if got[want] != 1 {
			t.Errorf("tenant header %q: expected exactly 1 occurrence (never shared with another goroutine, so never coalesced), got %d", want, got[want])
		}
	}
	if got[""] < 1 {
		t.Error("expected at least 1 request for the untenanted (\"\") case")
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
	// This test repeatedly re-fetches tenant A and tenant B (via the
	// cross-tenant-miss-triggered refreshes below); it's about
	// partitioning, not the separate minFetchInterval cooldown.
	f.minFetchInterval = 0

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

// TestFetcher_Fetch_BoundsTenantCacheSize is a regression test for a
// Copilot-review finding: the tenant is an unverified, attacker-influenced
// claim (see issuerRequestTenantID in the validator package), so without a
// bound an attacker sending many distinct syntactically-valid tenant values
// could grow the per-tenant cache without limit and force a fetch to the
// real JWKS endpoint for each one — memory and request-amplification DoS.
// It proves the cache never holds more than maxCachedTenants entries and
// evicts the least-recently-fetched tenant first.
func TestFetcher_Fetch_BoundsTenantCacheSize(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")
	// This test is specifically about the LRU size bound, not the separate
	// new-tenant admission rate limiter (see TestFetcher_Fetch_*Admission*
	// below) — relax the limiter so a fast sequential burst of
	// maxCachedTenants+1 distinct tenants isn't itself throttled.
	f.admissionLimit = maxCachedTenants * 2
	f.admissionWindow = time.Hour

	// Fetch one more tenant than the cache can hold, in order, then confirm
	// the very first (least-recently-fetched) tenant was evicted while the
	// most recent maxCachedTenants remain.
	for i := 0; i < maxCachedTenants+1; i++ {
		tenant := fmt.Sprintf("tenant-%d", i)
		if err := f.fetch(ContextWithTenantID(context.Background(), tenant)); err != nil {
			t.Fatalf("tenant %s: fetch failed: %v", tenant, err)
		}
	}

	f.mu.RLock()
	cacheSize := len(f.keySets)
	lruSize := f.lru.Len()
	f.mu.RUnlock()
	if cacheSize > maxCachedTenants {
		t.Fatalf("expected cache to hold at most %d entries, got %d", maxCachedTenants, cacheSize)
	}
	if lruSize != cacheSize {
		t.Fatalf("expected LRU tracking size (%d) to match cache size (%d)", lruSize, cacheSize)
	}

	if ks := f.KeySet("tenant-0"); ks != nil {
		t.Errorf("expected the least-recently-fetched tenant (tenant-0) to have been evicted, but it is still cached: %+v", ks)
	}
	lastTenant := fmt.Sprintf("tenant-%d", maxCachedTenants)
	if ks := f.KeySet(lastTenant); ks == nil {
		t.Errorf("expected the most-recently-fetched tenant (%s) to still be cached", lastTenant)
	}
}

// TestFetcher_Fetch_RateLimitsNewTenantAdmission is a regression test for a
// second-order Copilot-review finding on the cache-size bound above:
// bounding memory alone does not bound outbound requests, since cycling
// through more tenants than the cache holds still triggers one fetch per
// distinct value and repeatedly evicts entries. It proves a previously
// uncached tenant beyond the configured admission limit is refused
// (without ever calling the JWKS endpoint for it), while re-fetching an
// already-cached tenant is never subject to that limit.
func TestFetcher_Fetch_RateLimitsNewTenantAdmission(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")
	f.admissionShards = make([]admissionShard, 1) // single shard: exercise the total limit deterministically, not sharded fairness
	f.admissionLimit = 3
	f.admissionWindow = time.Hour // long window: no mid-test refill
	f.minFetchInterval = 0        // this test re-fetches tenant-0; unrelated to the cooldown

	for i := 0; i < 3; i++ {
		tenant := fmt.Sprintf("tenant-%d", i)
		if err := f.fetch(ContextWithTenantID(context.Background(), tenant)); err != nil {
			t.Fatalf("tenant %s: expected fetch within the admission limit to succeed, got: %v", tenant, err)
		}
	}

	// A 4th distinct, previously-uncached tenant exceeds the limit.
	if err := f.fetch(ContextWithTenantID(context.Background(), "tenant-over-limit")); err == nil {
		t.Error("expected a fetch for a new tenant beyond the admission limit to be refused")
	}

	// Re-fetching an already-cached tenant (one of the first 3) is not
	// subject to the new-tenant limit — it isn't "new".
	if err := f.fetch(ContextWithTenantID(context.Background(), "tenant-0")); err != nil {
		t.Errorf("expected re-fetching an already-cached tenant to succeed regardless of the new-tenant limit, got: %v", err)
	}
}

// TestFetcher_Fetch_ConfiguredTenantExemptFromEvictionAndAdmissionLimit
// proves the operator-configured tenant is immune to both protections
// added for the unverified, attacker-influenced tenant claim: it is never
// evicted by the bounded LRU cache to make room for other tenants, and it
// is never subject to the new-tenant admission rate limiter, regardless of
// how much unrelated tenant churn a caller (or attacker) generates.
func TestFetcher_Fetch_ConfiguredTenantExemptFromEvictionAndAdmissionLimit(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")
	f.cacheCapacity = 2
	f.admissionLimit = 2
	f.admissionWindow = time.Hour
	f.minFetchInterval = 0 // this test re-fetches the configured tenant twice; unrelated to the cooldown

	// protectedCtx simulates Start's internal refresh call: no per-call
	// tenant, explicitly marked as the internal path, so it resolves to
	// the configured tenant (see tenantForContext/internalRefreshContext).
	protectedCtx := internalRefreshContext(context.Background())
	if err := f.fetch(protectedCtx); err != nil {
		t.Fatalf("initial fetch for the configured tenant failed: %v", err)
	}

	// Exhaust both the tiny cache capacity and the admission limit with
	// unrelated tenants. Some of these are expected to be refused by the
	// admission limiter once it's exhausted — that's the point being
	// exercised, not a test failure.
	for i := 0; i < 5; i++ {
		tenant := fmt.Sprintf("attacker-tenant-%d", i)
		_ = f.fetch(ContextWithTenantID(context.Background(), tenant))
	}

	// The configured tenant's cache entry must still be there — the LRU
	// bound (cacheCapacity=2) would otherwise have evicted it long before
	// 5 unrelated tenants were admitted.
	if ks := f.KeySet("configured-tenant"); ks == nil {
		t.Fatal("expected the configured tenant's cache entry to survive unrelated tenant churn, but it was evicted")
	}

	// The configured tenant must also remain fetchable even after the
	// admission limiter above is exhausted by unrelated tenants.
	if err := f.fetch(protectedCtx); err != nil {
		t.Errorf("expected the configured tenant to remain exempt from the new-tenant admission limit, got: %v", err)
	}
}

// TestFetcher_Fetch_SpoofedTenantClaimNotExemptFromAdmissionLimit is a
// regression test for a Copilot-review finding: admitNewTenant used to
// exempt any request whose resolved tenant string equaled
// configuredTenantID, but that string is exactly what an unverified
// per-call claim can also carry — an attacker sending tenant/tenant_id
// equal to the (guessed or known) configured value got the same free pass
// as a genuine background-refresh call, bypassing the limiter entirely. It
// proves an explicit claim matching the configured tenant string is
// refused under a limit of 0, while the genuine fallback path (no per-call
// tenant at all) remains exempt under the same setting.
func TestFetcher_Fetch_SpoofedTenantClaimNotExemptFromAdmissionLimit(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")
	f.admissionLimit = 0 // refuse every non-fallback admission outright
	f.admissionWindow = time.Hour

	spoofedCtx := ContextWithTenantID(context.Background(), "configured-tenant")
	if err := f.fetch(spoofedCtx); err == nil {
		t.Error("expected an explicit claim matching the configured tenant string to be subject to the admission limit, not exempt")
	}

	if err := f.fetch(internalRefreshContext(context.Background())); err != nil {
		t.Errorf("expected the genuine fallback path (Start's internal refresh) to remain exempt from the admission limit, got: %v", err)
	}
}

// TestFetcher_Fetch_SpoofedTenantClaimDoesNotGetEvictionProtection is the
// eviction-side counterpart of the admission-bypass regression test above:
// it proves a cache slot is marked eviction-protected only when it was
// actually created by a genuine fallback-path fetch, never merely because
// its tenant string happens to equal the configured tenant. It simulates
// the worst case — an attacker's spoofed claim reaching the fetcher
// *before* any genuine background refresh ever does — and confirms the
// resulting entry is still evicted like any other once capacity is
// exceeded.
func TestFetcher_Fetch_SpoofedTenantClaimDoesNotGetEvictionProtection(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")
	f.cacheCapacity = 2
	f.admissionLimit = 10
	f.admissionWindow = time.Hour

	// An attacker's explicit claim reaches the fetcher first, with a
	// string value that happens to match the operator's configured
	// tenant — no genuine fallback fetch has happened yet.
	spoofedCtx := ContextWithTenantID(context.Background(), "configured-tenant")
	if err := f.fetch(spoofedCtx); err != nil {
		t.Fatalf("spoofed fetch failed: %v", err)
	}

	// Fill the rest of the small cache with unrelated tenants to force
	// eviction pressure once capacity is exceeded.
	if err := f.fetch(ContextWithTenantID(context.Background(), "other-tenant")); err != nil {
		t.Fatalf("other-tenant fetch failed: %v", err)
	}
	if err := f.fetch(ContextWithTenantID(context.Background(), "third-tenant")); err != nil {
		t.Fatalf("third-tenant fetch failed: %v", err)
	}

	// The spoofed entry was never created via the genuine fallback path,
	// so it must be evictable like any other non-protected entry — not
	// treated as protected merely because its string matches
	// configuredTenantID.
	if ks := f.KeySet("configured-tenant"); ks != nil {
		t.Error("expected the spoofed entry (created by an explicit claim, not the fallback path) to be evictable, but it survived as if protected")
	}
}

// TestFetcher_Fetch_ThrottlesRepeatedFetchesRegardlessOfExemption is a
// regression test for two related Copilot-review findings: bounding
// tenant *admission* (maxCachedTenants, admitNewTenant) does not bound
// refetch *rate* for a tenant that's already admitted. Neither the
// viaFallback exemption nor the "already cached" exemption in
// admitNewTenant say anything about how often GetKey's kid-miss path may
// re-trigger a fetch for the SAME tenant — and the kid is itself
// unverified and attacker-controlled, independent of tenant identity or
// admission status. It proves that once a tenant slot exists (the
// protected/fallback one, or an ordinary already-cached one), a rapid
// repeat fetch attempt for that same tenant is throttled.
func TestFetcher_Fetch_ThrottlesRepeatedFetchesRegardlessOfExemption(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")
	f.minFetchInterval = time.Hour // long window: no mid-test refill

	// First fetch for the protected/fallback tenant succeeds and creates
	// its LRU entry.
	if err := f.fetch(context.Background()); err != nil {
		t.Fatalf("initial fallback fetch failed: %v", err)
	}
	// A second attempt for the SAME tenant shortly after — simulating a
	// kid-miss-driven refetch — must be throttled, not silently exempted
	// just because this tenant is the protected/fallback one.
	if err := f.fetch(context.Background()); err == nil {
		t.Error("expected a rapid repeat fetch for the protected/fallback tenant to be throttled by minFetchInterval")
	}

	// The same protection applies to an ordinary, already-cached explicit
	// tenant — the "cached" exemption in admitNewTenant is not a license
	// to refetch it as fast as requests arrive.
	if err := f.fetch(ContextWithTenantID(context.Background(), "established-tenant")); err != nil {
		t.Fatalf("initial fetch for established-tenant failed: %v", err)
	}
	if err := f.fetch(ContextWithTenantID(context.Background(), "established-tenant")); err == nil {
		t.Error("expected a rapid repeat fetch for an already-cached tenant to be throttled by minFetchInterval")
	}
}

// TestFetcher_GetKey_ThrottlesRepeatedRefreshOnKidMiss is the GetKey-level
// counterpart of the fetch-throttling test above, exercising the actual
// attack path a Copilot review described: an attacker sending requests
// with no (or an invalidated) tenant claim resolves via the very same
// fallback path a genuine background refresh uses, and GetKey calls fetch
// on every single kid-miss. Without a cooldown, repeatedly sending
// distinct, nonexistent kid values would force a fresh outbound JWKS
// fetch on every single request. It proves that after the first
// kid-miss-triggered fetch, a second kid-miss for the same tenant shortly
// after never reaches the network at all.
func TestFetcher_GetKey_ThrottlesRepeatedRefreshOnKidMiss(t *testing.T) {
	var reqCount int32
	ks := testKeySet(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)

	f := NewFetcher(ts.URL, 0, nil, "")
	f.minFetchInterval = time.Hour

	ctx := context.Background() // no per-call tenant: the common, untenanted case

	if _, err := f.GetKey(ctx, "nonexistent-kid-1"); err == nil {
		t.Fatal("expected an error for a kid that doesn't exist in the JWKS")
	}
	if _, err := f.GetKey(ctx, "nonexistent-kid-2"); err == nil {
		t.Fatal("expected the second, rapid kid-miss lookup to also fail (throttled)")
	}

	if got := atomic.LoadInt32(&reqCount); got != 1 {
		t.Errorf("expected exactly 1 outbound JWKS request across both kid-miss lookups (the second should have been throttled before reaching the network), got %d", got)
	}
}

// TestFetcher_Fetch_UpgradesExistingSlotToProtectedOnGenuineFallback is a
// regression test for a Copilot-review finding: touchTenantLocked's
// existing-entry branch used to only move the LRU node to the front,
// discarding viaFallback — so a slot an attacker's spoofed claim created
// first (protected=false) stayed unprotected forever, even once a genuine
// fallback fetch later claimed the very same tenant string. Unrelated
// tenant churn could then evict the operator-configured slot despite the
// documented exemption. It proves the slot IS upgraded to protected once
// a genuine fallback fetch reuses it, and survives eviction pressure
// afterward.
func TestFetcher_Fetch_UpgradesExistingSlotToProtectedOnGenuineFallback(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")
	f.cacheCapacity = 2
	f.admissionLimit = 10
	f.admissionWindow = time.Hour
	f.minFetchInterval = 0 // this test deliberately re-fetches the same tenant string

	// An attacker's explicit claim reaches the fetcher first — creates an
	// UNPROTECTED entry for "configured-tenant".
	spoofedCtx := ContextWithTenantID(context.Background(), "configured-tenant")
	if err := f.fetch(spoofedCtx); err != nil {
		t.Fatalf("spoofed fetch failed: %v", err)
	}

	// A genuine fallback fetch (e.g. Start's internal refresh) later
	// claims the SAME tenant string — this must upgrade the existing
	// entry to protected.
	if err := f.fetch(internalRefreshContext(context.Background())); err != nil {
		t.Fatalf("genuine fallback fetch failed: %v", err)
	}

	// Fill the rest of the small cache with an unrelated tenant, then add
	// one more to force eviction pressure.
	if err := f.fetch(ContextWithTenantID(context.Background(), "other-tenant")); err != nil {
		t.Fatalf("other-tenant fetch failed: %v", err)
	}
	if err := f.fetch(ContextWithTenantID(context.Background(), "third-tenant")); err != nil {
		t.Fatalf("third-tenant fetch failed: %v", err)
	}

	// The now-protected "configured-tenant" slot must have survived —
	// "other-tenant" (the only remaining non-protected entry) should have
	// been evicted instead.
	if ks := f.KeySet("configured-tenant"); ks == nil {
		t.Error("expected the configured tenant's slot to survive after being upgraded to protected by a genuine fallback fetch, but it was evicted")
	}
}

// TestFetcher_GetKey_TenantlessRequestNeverUsesConfiguredTenant is a
// regression test for a Copilot-review finding: Config.TenantID (the
// static fallback) is documented as being for Start's internal background
// refresh only, but tenantForContext used to apply it to ANY call whose
// ctx carried no per-call tenant — including ordinary, external,
// request-driven GetKey lookups whose token simply has no tenant claim at
// all. That could silently route a genuinely tenantless request to the
// WRONG tenant's JWKS slot and header. It proves an ordinary GetKey call
// with no per-call tenant resolves to the plain untenanted ("") slot and
// sends no X-Tenant-ID header, never the configured tenant's, even with a
// configured tenant set.
func TestFetcher_GetKey_TenantlessRequestNeverUsesConfiguredTenant(t *testing.T) {
	tenants := &tenantRecorder{}
	ts := testJWKSServer(t, tenants)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")

	// An ordinary request-driven GetKey call with no per-call tenant — NOT
	// Start's internal refresh (see internalRefreshContext).
	if _, err := f.GetKey(context.Background(), "test-kid"); err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	headers := tenants.all()
	if len(headers) != 1 {
		t.Fatalf("expected 1 request, got %d", len(headers))
	}
	if headers[0] != "" {
		t.Errorf("expected an ordinary tenantless request to send no X-Tenant-ID header, got %q (misrouted to the configured tenant)", headers[0])
	}

	if ks := f.KeySet("configured-tenant"); ks != nil {
		t.Error("expected the configured tenant's slot to remain untouched by an ordinary tenantless request")
	}
	if ks := f.KeySet(""); ks == nil {
		t.Error("expected the ordinary tenantless request to populate the plain \"\" slot instead")
	}
}

// TestFetcher_CommitFetchResult_DiscardsStaleGenerations is a regression
// test for a Copilot-review finding: fetch's HTTP round-trip runs without
// holding f.mu, so a slow response could otherwise resurrect an evicted
// entry (with no corresponding LRU node, breaking the cacheCapacity
// bound) or overwrite a newer attempt's fresher keys with an older,
// superseded one's stale response. It exercises commitFetchResultLocked
// directly to prove: (a) a response for a tenant whose slot doesn't exist
// (never admitted, or already evicted) is discarded, never resurrecting
// keySets without a corresponding LRU entry; and (b) a response carrying
// an outdated generation (superseded by a newer, already-admitted attempt
// for the same tenant) is discarded rather than overwriting the newer
// attempt's keys.
func TestFetcher_CommitFetchResult_DiscardsStaleGenerations(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")
	f.minFetchInterval = 0

	staleKS := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "stale-key"}}}
	freshKS := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "fresh-key"}}}

	// (a) A response for a tenant with no LRU entry at all must be
	// discarded, not resurrected into keySets.
	f.mu.Lock()
	f.commitFetchResultLocked("never-admitted-tenant", fetchAttempt{incarnation: 1, seq: 1}, staleKS)
	f.mu.Unlock()
	if ks := f.KeySet("never-admitted-tenant"); ks != nil {
		t.Error("expected a response for a tenant with no LRU entry to be discarded, not resurrected into keySets")
	}

	// (b) Simulate two attempts for the same tenant: an older one whose
	// response arrives late, after a newer attempt has already been
	// admitted and committed its own, fresher response.
	f.mu.Lock()
	_, olderAttempt := f.touchTenantLocked("race-tenant", false)
	f.mu.Unlock()

	f.mu.Lock()
	_, newerAttempt := f.touchTenantLocked("race-tenant", false)
	f.mu.Unlock()
	if newerAttempt == olderAttempt {
		t.Fatalf("expected two distinct attempts for the same tenant to get different fetchAttempt values, both got %+v", olderAttempt)
	}

	// The newer attempt's response arrives and commits first.
	f.mu.Lock()
	f.commitFetchResultLocked("race-tenant", newerAttempt, freshKS)
	f.mu.Unlock()

	// The OLDER attempt's response arrives late and must be discarded,
	// not overwrite the fresher keys.
	f.mu.Lock()
	f.commitFetchResultLocked("race-tenant", olderAttempt, staleKS)
	f.mu.Unlock()

	ks := f.KeySet("race-tenant")
	if ks == nil || len(ks.Keys) != 1 || ks.Keys[0].KeyID != "fresh-key" {
		t.Errorf("expected the newer attempt's keys to survive a stale, older attempt's late response, got %+v", ks)
	}
}

// TestFetcher_CommitFetchResult_OlderAttemptStillCommitsIfNewerNeverDid is
// a regression test for a Copilot-review finding: an earlier version
// compared against the last ATTEMPTED (admitted) seq rather than the last
// COMMITTED one. fetch's HTTP round-trip runs without holding f.mu, so a
// slower attempt can still be in flight when a later attempt for the same
// tenant is admitted; if that later attempt then fails (network error,
// non-200, etc.) it never calls commitFetchResultLocked at all. The
// earlier, slower attempt's eventual SUCCESS must not be discarded just
// because a newer attempt was merely admitted and then failed — only an
// attempt whose response actually landed should be able to supersede an
// older one. It proves an older attempt still commits successfully when
// no newer attempt for the same tenant has actually committed.
func TestFetcher_CommitFetchResult_OlderAttemptStillCommitsIfNewerNeverDid(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")
	f.minFetchInterval = 0

	f.mu.Lock()
	_, olderAttempt := f.touchTenantLocked("slow-tenant", false)
	f.mu.Unlock()

	// A second attempt is admitted (e.g. another request's kid-miss
	// arrives before the first, slow fetch returns) but its HTTP request
	// fails — fetch would never call commitFetchResultLocked for it at
	// all, so nothing commits for this attempt.
	f.mu.Lock()
	_, _ = f.touchTenantLocked("slow-tenant", false)
	f.mu.Unlock()

	// The first, slower attempt finally succeeds. It must still be able
	// to commit — nothing newer has actually landed.
	successKS := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "success-key"}}}
	f.mu.Lock()
	f.commitFetchResultLocked("slow-tenant", olderAttempt, successKS)
	f.mu.Unlock()

	ks := f.KeySet("slow-tenant")
	if ks == nil || len(ks.Keys) != 1 || ks.Keys[0].KeyID != "success-key" {
		t.Errorf("expected the older attempt's successful response to commit since no newer attempt ever did, got %+v", ks)
	}
}

// TestFetcher_CommitFetchResult_GenerationsUniqueAcrossEvictionAndReadmission
// is a regression test for a Copilot-review finding on the generation
// mechanism itself: an earlier version reset a tenant's generation
// counter to 1 whenever its slot was newly created — including when it
// was RE-created after being evicted. A stale, still-in-flight fetch from
// BEFORE the eviction could then coincidentally carry the exact same
// generation number as a fresh (re-)admission afterward, letting
// commitFetchResultLocked mistake the stale response for current and
// overwrite fresher keys. It proves a generation captured BEFORE a
// tenant's eviction is never reused by a later re-admission of the same
// tenant, and that the stale response is correctly discarded.
func TestFetcher_CommitFetchResult_GenerationsUniqueAcrossEvictionAndReadmission(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")
	f.cacheCapacity = 1
	f.minFetchInterval = 0
	f.admissionLimit = 100 // this test is about generation uniqueness, not admission limits

	// Admit "victim-tenant" and capture its attempt — simulating a slow
	// fetch that's still in flight (attempt captured, response not yet
	// committed).
	f.mu.Lock()
	_, staleAttempt := f.touchTenantLocked("victim-tenant", false)
	f.mu.Unlock()

	// Evict "victim-tenant" by admitting a different tenant into a cache
	// with capacity 1.
	f.mu.Lock()
	_, _ = f.touchTenantLocked("other-tenant", false)
	f.mu.Unlock()
	if ks := f.KeySet("victim-tenant"); ks != nil {
		t.Fatal("expected victim-tenant to have been evicted to make room")
	}

	// Re-admit "victim-tenant" — e.g. a fresh, legitimate request for it
	// arrives — and let its own fetch commit first.
	f.mu.Lock()
	_, freshAttempt := f.touchTenantLocked("victim-tenant", false)
	f.mu.Unlock()
	if freshAttempt.incarnation == staleAttempt.incarnation {
		t.Fatalf("expected the re-admitted tenant's incarnation (%d) to differ from the stale, pre-eviction one (%d)", freshAttempt.incarnation, staleAttempt.incarnation)
	}

	freshKS := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "fresh-key"}}}
	f.mu.Lock()
	f.commitFetchResultLocked("victim-tenant", freshAttempt, freshKS)
	f.mu.Unlock()

	// The stale, pre-eviction fetch (captured staleAttempt) finally
	// "returns" and must not be mistaken for current.
	staleKS := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "stale-key"}}}
	f.mu.Lock()
	f.commitFetchResultLocked("victim-tenant", staleAttempt, staleKS)
	f.mu.Unlock()

	ks := f.KeySet("victim-tenant")
	if ks == nil || len(ks.Keys) != 1 || ks.Keys[0].KeyID != "fresh-key" {
		t.Errorf("expected the fresh (re-admitted) generation's keys to survive a stale pre-eviction generation's late response, got %+v", ks)
	}
}

// TestFetcher_Fetch_AdmissionChargedAtomicallyUnderConcurrentChurn is a
// regression test for a "previously missed" Copilot-review finding: an
// earlier version of admission control read "is this tenant cached" via
// a separate lock acquisition that was released before touchTenantLocked
// ran — a concurrent eviction between those two steps could let a
// re-admission through without ever consuming the admission budget.
// touchTenantLocked now decides cache presence, admission charging, and
// eviction/creation all under one continuously-held lock, so the total
// number of admissions can never exceed admissionLimit, no matter how
// much concurrent churn (many distinct tenants racing for a
// deliberately tiny cache capacity, forcing constant eviction) is thrown
// at it. Run with -race; this asserts an exact invariant (not a
// probabilistic reproduction of the old race), so it holds deterministically
// on the fixed code regardless of scheduling.
func TestFetcher_Fetch_AdmissionChargedAtomicallyUnderConcurrentChurn(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")
	f.cacheCapacity = 1                           // forces eviction on every new tenant admitted
	f.admissionShards = make([]admissionShard, 1) // single shard: this test exercises the total admission budget, not sharded fairness
	f.admissionLimit = 5
	f.admissionWindow = time.Hour
	f.minFetchInterval = 0

	// Under this deliberately extreme churn (cacheCapacity=1, 50 racing
	// distinct tenants), many individual fetch() calls legitimately fail
	// even after being charged once: their slot gets evicted before
	// commit, their bounded retry re-admits, and that retry can itself be
	// refused once the shared budget is exhausted — the budget correctly
	// applying to retries too, not a bug. So "count successful calls" is
	// no longer a valid proxy for "count admission charges"; the actual
	// invariant this test cares about — the shard's charge count never
	// exceeds its limit, no matter how much concurrent churn hits it — is
	// checked directly instead.
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tenant := fmt.Sprintf("tenant-%d", i)
			_ = f.fetch(ContextWithTenantID(context.Background(), tenant))
		}(i)
	}
	wg.Wait()

	f.mu.RLock()
	shardCount := f.admissionShards[0].count
	f.mu.RUnlock()
	if shardCount > f.admissionLimit {
		t.Errorf("expected the admission shard's charge count to never exceed its limit (%d) despite concurrent churn, got %d — admission budget was bypassed", f.admissionLimit, shardCount)
	}
}

// TestFetcher_Fetch_RejectsAdmissionWhenNothingEvictable is a regression
// test for a Copilot-review finding: with cacheCapacity == 1 and the
// cache's sole entry being the protected (fallback) tenant, an admission
// attempt for a different, non-protected tenant used to still create a
// new slot even though nothing could be evicted to make room — silently
// growing the cache past cacheCapacity. It proves such an admission is
// now refused instead, and that the admission-budget charge for the
// refused attempt is rolled back (not permanently consumed).
func TestFetcher_Fetch_RejectsAdmissionWhenNothingEvictable(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")
	f.cacheCapacity = 1
	f.admissionLimit = 5
	f.admissionWindow = time.Hour
	f.minFetchInterval = 0

	// Populate the sole slot with the protected/fallback tenant.
	if err := f.fetch(internalRefreshContext(context.Background())); err != nil {
		t.Fatalf("initial fallback fetch failed: %v", err)
	}

	// A different tenant now has nothing to evict — the only entry is
	// protected. This admission must be refused, and the cache must stay
	// at exactly 1 entry.
	if err := f.fetch(ContextWithTenantID(context.Background(), "other-tenant")); err == nil {
		t.Error("expected admission to be refused when no evictable entry exists, but it succeeded")
	}
	if ks := f.KeySet("other-tenant"); ks != nil {
		t.Error("expected the refused tenant to have no cache entry")
	}
	if ks := f.KeySet("configured-tenant"); ks == nil {
		t.Error("expected the protected tenant's entry to remain")
	}

	f.mu.RLock()
	cacheSize := len(f.keySets)
	f.mu.RUnlock()
	if cacheSize != 1 {
		t.Errorf("expected the cache to still hold exactly 1 entry (cacheCapacity), got %d", cacheSize)
	}

	// The refused attempt's admission-budget charge must have been rolled
	// back, not permanently consumed. Simplest direct check: the specific
	// shard "other-tenant" hashes into is back to a count of 0.
	f.mu.RLock()
	shardCount := f.admissionShards[f.admissionShardIndex("other-tenant")].count
	f.mu.RUnlock()
	if shardCount != 0 {
		t.Errorf("expected the refused admission's budget charge to be rolled back to 0, got %d", shardCount)
	}
}

// TestFetcher_Fetch_ThrottledFallbackStillUpgradesProtection is a
// regression test for a Copilot-review finding: the protected-upgrade
// logic in touchTenantLocked used to run AFTER the minFetchInterval
// cooldown check, so a genuine fallback attempt arriving within the
// cooldown window of an earlier, spoofed-claim-created slot was throttled
// before it ever got to mark that slot protected — leaving it evictable
// until some later, untethered fallback attempt happened to land outside
// the cooldown window. It proves a throttled fallback attempt still
// upgrades the slot to protected, even though the attempt itself is
// refused (no network call happens for it).
func TestFetcher_Fetch_ThrottledFallbackStillUpgradesProtection(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")
	f.cacheCapacity = 2
	f.admissionLimit = 10
	f.admissionWindow = time.Hour
	f.minFetchInterval = time.Hour // long cooldown: the second call below is deliberately throttled

	// An attacker's explicit claim reaches the fetcher first — creates an
	// UNPROTECTED entry for "configured-tenant".
	spoofedCtx := ContextWithTenantID(context.Background(), "configured-tenant")
	if err := f.fetch(spoofedCtx); err != nil {
		t.Fatalf("spoofed fetch failed: %v", err)
	}

	// A genuine fallback attempt arrives within the cooldown window and
	// is throttled (no network call) — but it must still upgrade the slot
	// to protected.
	if err := f.fetch(internalRefreshContext(context.Background())); err == nil {
		t.Fatal("expected the fallback attempt within the cooldown window to be throttled")
	}

	// Fill the rest of the small cache with an unrelated tenant, then add
	// one more to force eviction pressure.
	if err := f.fetch(ContextWithTenantID(context.Background(), "other-tenant")); err != nil {
		t.Fatalf("other-tenant fetch failed: %v", err)
	}
	if err := f.fetch(ContextWithTenantID(context.Background(), "third-tenant")); err != nil {
		t.Fatalf("third-tenant fetch failed: %v", err)
	}

	// The now-protected "configured-tenant" slot must have survived even
	// though the fallback attempt that upgraded it was itself throttled —
	// "other-tenant" (the only non-protected entry left) should have been
	// evicted instead.
	if ks := f.KeySet("configured-tenant"); ks == nil {
		t.Error("expected the configured tenant's slot to survive eviction pressure after being upgraded to protected by a THROTTLED fallback attempt, but it was evicted")
	}
}

// TestFetcher_GetKey_ConcurrentCacheMissesCoalesceInsteadOfFailing is a
// regression test for a Copilot-review finding: the minFetchInterval
// cooldown made concurrent cache-miss lookups for the SAME tenant fail
// spuriously. The first GetKey call creates the tenant slot and starts
// the (slow) HTTP fetch; any other concurrent call for the same
// tenant/kid used to see the slot already exists, get throttled by
// touchTenantLocked, and return an error immediately without ever
// rechecking the cache — even though the first call's in-flight fetch
// was about to populate exactly the keys it needed (e.g. right after a
// cold start or a key rotation, when many requests arrive at once). It
// proves many concurrent GetKey calls for the same tenant hitting a cold
// cache simultaneously all succeed, coalesced onto the single in-flight
// fetch rather than each independently risking the cooldown.
func TestFetcher_GetKey_ConcurrentCacheMissesCoalesceInsteadOfFailing(t *testing.T) {
	ks := testKeySet(t)
	var reqCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		time.Sleep(50 * time.Millisecond) // widen the race window so concurrent callers reliably overlap
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)

	f := NewFetcher(ts.URL, 0, nil, "")
	f.minFetchInterval = time.Hour // deliberately long: without coalescing, every follower would be throttled

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.GetKey(context.Background(), "test-kid"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("expected concurrent cache-miss lookups to succeed via coalescing, got: %v", err)
	}

	if got := atomic.LoadInt32(&reqCount); got == 0 {
		t.Error("expected at least 1 outbound JWKS request")
	}
}

// TestFetcher_Fetch_FollowerHonorsContextCancellation is a regression test
// for a Copilot-review finding: a follower joining an in-flight fetch (see
// fetch's coalescing) used to wait unconditionally on the leader's
// channel, never observing its own context's cancellation. If the leader
// were stuck on a stalled JWKS endpoint, a canceled follower would block
// until the unrelated leader finished, letting goroutines accumulate and
// defeating request deadlines. It proves a follower whose context is
// already canceled returns promptly with the context error instead of
// waiting for a slow leader.
func TestFetcher_Fetch_FollowerHonorsContextCancellation(t *testing.T) {
	ks := testKeySet(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // wide enough for the follower to reliably join, then cancel
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)

	f := NewFetcher(ts.URL, 0, nil, "")

	leaderDone := make(chan error, 1)
	go func() {
		leaderDone <- f.fetch(context.Background())
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		_, inFlight := f.inFlightFetches[""]
		f.mu.Unlock()
		if inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the leader fetch to register as in-flight")
		}
		time.Sleep(time.Millisecond)
	}

	followerCtx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- f.fetch(followerCtx) }()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected the follower to return context.Canceled, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("follower did not honor its own context cancellation and blocked on the stalled leader")
	}

	if err := <-leaderDone; err != nil {
		t.Fatalf("leader fetch failed: %v", err)
	}
}

// TestFetcher_Fetch_CoalescedFallbackStillUpgradesProtection is a
// regression test for a Copilot-review finding: a genuine fallback call
// (e.g. Start's ticker) that joins an in-flight fetch as a follower (see
// fetch's coalescing) used to skip touchTenantLocked entirely — including
// its protected-upgrade logic — since a follower doesn't perform admission
// or the network round-trip itself. A slot an attacker's spoofed claim
// created and is currently (slowly) fetching could therefore stay
// unprotected even though the fallback path genuinely ran concurrently
// with it. It proves a fallback call joining as a follower still upgrades
// the slot to protected, which then survives subsequent eviction
// pressure.
func TestFetcher_Fetch_CoalescedFallbackStillUpgradesProtection(t *testing.T) {
	ks := testKeySet(t)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)

	f := NewFetcher(ts.URL, 0, nil, "configured-tenant")
	f.cacheCapacity = 2
	f.admissionLimit = 10
	f.admissionWindow = time.Hour
	f.minFetchInterval = 0

	// An attacker's explicit claim becomes the leader for
	// "configured-tenant" — a slow request, still in flight.
	leaderDone := make(chan error, 1)
	go func() {
		leaderDone <- f.fetch(ContextWithTenantID(context.Background(), "configured-tenant"))
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		_, inFlight := f.inFlightFetches["configured-tenant"]
		f.mu.Unlock()
		if inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the leader fetch to register as in-flight")
		}
		time.Sleep(time.Millisecond)
	}

	// A genuine fallback call joins as a follower while the spoofed
	// claim's fetch is still in flight.
	followerDone := make(chan error, 1)
	go func() {
		followerDone <- f.fetch(internalRefreshContext(context.Background()))
	}()
	time.Sleep(50 * time.Millisecond) // let the follower observe in-flight and apply the upgrade

	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader fetch failed: %v", err)
	}
	if err := <-followerDone; err != nil {
		t.Fatalf("coalesced fallback fetch failed: %v", err)
	}

	// Fill the rest of the small cache with unrelated tenants to force
	// eviction pressure.
	if err := f.fetch(ContextWithTenantID(context.Background(), "other-tenant")); err != nil {
		t.Fatalf("other-tenant fetch failed: %v", err)
	}
	if err := f.fetch(ContextWithTenantID(context.Background(), "third-tenant")); err != nil {
		t.Fatalf("third-tenant fetch failed: %v", err)
	}

	if ks := f.KeySet("configured-tenant"); ks == nil {
		t.Error("expected the configured tenant's slot to survive eviction pressure after being upgraded to protected by a COALESCED fallback call, but it was evicted")
	}
}

// TestFetcher_Fetch_AdmissionShardingIsolatesFloodedTenants is a
// regression test for a Copilot-review finding: a single, global
// admission counter shared by every non-fallback tenant let a flood of
// distinct unverified tenant claims exhaust the entire new-tenant
// admission budget, starving a legitimate, never-before-seen tenant that
// had not itself exceeded any limit. It proves that exhausting one
// admission shard (see admissionShardIndex) does not affect a distinct
// tenant hashing into a different shard, while a second distinct tenant
// hashing into the SAME (exhausted) shard is still correctly refused.
func TestFetcher_Fetch_AdmissionShardingIsolatesFloodedTenants(t *testing.T) {
	ts := testPerTenantJWKSServer(t)
	f := NewFetcher(ts.URL, 0, nil, "")
	f.admissionShards = make([]admissionShard, 2)
	f.admissionLimit = 1
	f.admissionWindow = time.Hour
	f.minFetchInterval = 0

	// Find two tenant strings that hash to different shards, and a third
	// that hashes to the SAME shard as the first.
	var shard0Tenant, shard0Tenant2, shard1Tenant string
	for i := 0; shard0Tenant == "" || shard0Tenant2 == "" || shard1Tenant == ""; i++ {
		if i > 10000 {
			t.Fatal("could not find tenant strings covering both shards")
		}
		tenant := fmt.Sprintf("tenant-%d", i)
		switch f.admissionShardIndex(tenant) {
		case 0:
			if shard0Tenant == "" {
				shard0Tenant = tenant
			} else if shard0Tenant2 == "" {
				shard0Tenant2 = tenant
			}
		case 1:
			if shard1Tenant == "" {
				shard1Tenant = tenant
			}
		}
	}

	// Exhaust shard 0's budget (limit 1) with the first tenant.
	if err := f.fetch(ContextWithTenantID(context.Background(), shard0Tenant)); err != nil {
		t.Fatalf("first admission into shard 0 failed: %v", err)
	}

	// A second, distinct tenant hashing into the SAME (now exhausted)
	// shard must be refused.
	if err := f.fetch(ContextWithTenantID(context.Background(), shard0Tenant2)); err == nil {
		t.Error("expected a second distinct tenant hashing to the same, exhausted shard to be refused")
	}

	// A tenant hashing into the OTHER shard must be entirely unaffected
	// by shard 0's exhaustion — this is the fairness property sharding
	// provides over a single shared counter.
	if err := f.fetch(ContextWithTenantID(context.Background(), shard1Tenant)); err != nil {
		t.Errorf("expected a tenant hashing to a different shard to remain unaffected by shard 0's exhaustion, got: %v", err)
	}
}

// TestFetcher_Fetch_RetriesWhenOwnSlotEvictedWhileInFlight is a regression
// test for a previously-missed Copilot-review finding: fetch's HTTP
// round-trip runs without holding f.mu, so a tenant's own slot can be
// evicted by an UNRELATED admission while its fetch is still in flight.
// commitFetchResultLocked correctly discards the resulting response as
// stale (see commitDiscardedEvicted), but without a retry the caller
// would see a spurious "no keys available" failure despite the fetch
// having actually succeeded over the network. It proves the fetch
// transparently retries — re-admitting the tenant fresh — and succeeds.
func TestFetcher_Fetch_RetriesWhenOwnSlotEvictedWhileInFlight(t *testing.T) {
	ks := testKeySet(t)
	release := make(chan struct{})
	var reqCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&reqCount, 1) == 1 {
			<-release // hold only the FIRST request (victim-tenant's original attempt) open
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)

	f := NewFetcher(ts.URL, 0, nil, "")
	f.cacheCapacity = 1 // any other admission evicts victim-tenant's sole slot
	f.admissionLimit = 10
	f.admissionWindow = time.Hour
	f.minFetchInterval = 0

	victimDone := make(chan error, 1)
	go func() {
		victimDone <- f.fetch(ContextWithTenantID(context.Background(), "victim-tenant"))
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		_, inFlight := f.inFlightFetches["victim-tenant"]
		f.mu.Unlock()
		if inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for victim-tenant's fetch to register as in-flight")
		}
		time.Sleep(time.Millisecond)
	}

	// Admit an unrelated tenant — with cacheCapacity=1, this evicts
	// victim-tenant's slot while its own fetch is still in flight.
	if err := f.fetch(ContextWithTenantID(context.Background(), "evictor-tenant")); err != nil {
		t.Fatalf("evictor-tenant fetch failed: %v", err)
	}
	if ks := f.KeySet("victim-tenant"); ks != nil {
		t.Fatal("expected victim-tenant to have been evicted while its own fetch was in flight")
	}

	// Release victim-tenant's held response — it must retry and succeed,
	// not return a spurious error.
	close(release)
	if err := <-victimDone; err != nil {
		t.Errorf("expected victim-tenant's fetch to succeed via retry after its slot was evicted mid-flight, got: %v", err)
	}
	if ks := f.KeySet("victim-tenant"); ks == nil {
		t.Error("expected victim-tenant's keys to be present in the cache after the retry committed")
	}
}
