// Package jwks provides a JWKS fetcher with background refresh for validating
// AS-issued access tokens. It fetches the JSON Web Key Set from the AS's
// /.well-known/jwks.json endpoint and caches the keys.
package jwks

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// maxCachedTenants bounds the per-tenant key cache. The cache key comes
// from an unverified, attacker-influenced claim (see tenantForContext and
// issuerRequestTenantID in the validator package) — without a bound, an
// attacker sending many syntactically-valid-looking but distinct tenant
// values could grow the cache without limit (memory DoS). When the cache
// is at capacity, the least-recently-fetched tenant's entry is evicted to
// make room for a new one — except the operator-configured tenant (see
// protectedTenant), which is never evicted.
//
// maxCachedTenants alone does not bound the resulting *request*
// amplification: an attacker cycling through more than maxCachedTenants
// distinct tenants can still force one outbound JWKS fetch per distinct
// value, indefinitely, and repeatedly evict every non-protected entry.
// maxNewTenantFetchesPerWindow/newTenantFetchWindow (see admitNewTenant)
// bound that separately, by rate-limiting fetches for tenants not already
// cached.
const maxCachedTenants = 256

// maxNewTenantFetchesPerWindow and newTenantFetchWindow bound how many
// previously-uncached tenants may trigger an outbound JWKS fetch within a
// given window (see admitNewTenant). Already-cached tenants and the
// operator-configured tenant (see protectedTenant) are exempt and never
// count against this limit.
const (
	maxNewTenantFetchesPerWindow = 64
	newTenantFetchWindow         = time.Second
)

// Fetcher maintains cached copies of JWKS keys from a remote endpoint,
// partitioned per tenant.
//
// Fetcher instances are shared across concurrent callers (e.g. one Fetcher
// per Validator, serving every request that Validator handles). Nothing
// derived from a single caller's unverified claims may be stored as a
// scalar field on the struct itself, since that would leak between
// unrelated callers sharing the instance — see ContextWithTenantID, which
// is threaded through per call via context.Context instead. The key cache
// (keySets) is deliberately a map keyed by tenant rather than a single
// shared value: a cache hit for one tenant must never be served to a
// lookup for a different tenant, so every fetch and lookup resolves and
// uses the same effective tenant key (see tenantForContext) throughout.
// The untenanted case (no per-call tenant and no configuredTenantID) uses
// the empty string as its own, separate slot.
type Fetcher struct {
	url     string
	refresh time.Duration
	client  *http.Client
	mu      sync.RWMutex
	keySets map[string]*jose.JSONWebKeySet
	// lru and lruElems bound keySets to maxCachedTenants entries (see its
	// doc comment): lru's front is the most-recently-fetched tenant, back
	// is the least-recently-fetched and the next to be evicted.
	lru      *list.List
	lruElems map[string]*list.Element
	// cacheCapacity defaults to maxCachedTenants; only overridden by tests
	// to exercise eviction without a large number of fetches.
	cacheCapacity int
	lastFetch     time.Time
	cancel        context.CancelFunc

	// configuredTenantID is a static, operator-configured tenant identifier
	// supplied once at construction time (from validator.Config.TenantID).
	// Unlike a per-request tenant (see ContextWithTenantID), it is NOT
	// derived from any unverified JWT claim, never mutates after
	// construction, and so cannot leak between callers sharing this
	// Fetcher. It exists solely as the tenant fallback for
	// background-refresh fetches (Start's ticker), which run on the
	// context passed to Start and so never carry a per-call tenant of
	// their own; a real, per-call fetch always prefers ctx's tenant over
	// this value. It also identifies the one tenant slot that is exempt
	// from LRU eviction and new-tenant rate limiting — see
	// protectedTenant.
	configuredTenantID string

	// admissionMu, admissionCount and admissionResetAt implement the
	// new-tenant fetch rate limiter described at
	// maxNewTenantFetchesPerWindow. admissionLimit/admissionWindow default
	// to those constants; only overridden by tests for determinism.
	admissionMu      sync.Mutex
	admissionCount   int
	admissionResetAt time.Time
	admissionLimit   int
	admissionWindow  time.Duration
}

type tenantIDContextKey struct{}

// ContextWithTenantID attaches a tenant ID to ctx for issuer-bound requests.
func ContextWithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey{}, tenantID)
}

// NewFetcher creates a JWKS fetcher for the given URL.
// If refreshInterval is 0, defaults to 5 minutes.
// If client is nil, http.DefaultClient is used.
// configuredTenantID, if non-empty, is a static, operator-configured tenant
// identifier used as the X-Tenant-ID header for background-refresh fetches,
// which have no per-call tenant of their own. Per-call fetches driven by a
// real request (see ContextWithTenantID) always take precedence over it.
func NewFetcher(url string, refreshInterval time.Duration, client *http.Client, configuredTenantID string) *Fetcher {
	if refreshInterval == 0 {
		refreshInterval = 5 * time.Minute
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &Fetcher{
		url:                url,
		refresh:            refreshInterval,
		client:             client,
		keySets:            make(map[string]*jose.JSONWebKeySet),
		lru:                list.New(),
		lruElems:           make(map[string]*list.Element),
		cacheCapacity:      maxCachedTenants,
		configuredTenantID: configuredTenantID,
		admissionLimit:     maxNewTenantFetchesPerWindow,
		admissionWindow:    newTenantFetchWindow,
	}
}

// protectedTenant returns the one tenant slot that is exempt from LRU
// eviction and from the new-tenant fetch rate limiter: the
// operator-configured tenant if one was set at construction, otherwise the
// untenanted default slot (""). Both represent legitimate, static
// configuration rather than attacker-controlled input, so churn from other
// (attacker-influenced) tenants must never starve or evict it.
func (f *Fetcher) protectedTenant() string {
	return f.configuredTenantID
}

// touchTenantLocked records tenant as the most-recently-fetched entry,
// evicting the least-recently-fetched non-protected tenant's cache slot
// first if tenant is new and the cache is already at cacheCapacity. Caller
// must hold f.mu (write lock).
func (f *Fetcher) touchTenantLocked(tenant string) {
	if el, ok := f.lruElems[tenant]; ok {
		f.lru.MoveToFront(el)
		return
	}
	if f.lru.Len() >= f.cacheCapacity {
		protected := f.protectedTenant()
		for oldest := f.lru.Back(); oldest != nil; oldest = oldest.Prev() {
			oldTenant, _ := oldest.Value.(string) // always a string: only touchTenantLocked pushes onto lru
			if oldTenant == protected {
				continue // never evict the operator-configured/default slot
			}
			f.lru.Remove(oldest)
			delete(f.lruElems, oldTenant)
			delete(f.keySets, oldTenant)
			break
		}
		// If every existing entry is the protected tenant (only possible
		// with cacheCapacity == 1), nothing is evicted and the cache
		// simply grows by one rather than evicting protected state.
	}
	f.lruElems[tenant] = f.lru.PushFront(tenant)
}

// admitNewTenant reports whether ctx's tenant may trigger an outbound JWKS
// fetch right now. The protected tenant (see protectedTenant) and any
// tenant already present in the cache always are; any other tenant is
// subject to admissionLimit/admissionWindow, so an attacker cycling
// through many distinct unverified tenant claims cannot generate unbounded
// outbound requests to the JWKS endpoint or repeatedly evict legitimate
// cache entries by forcing constant churn.
func (f *Fetcher) admitNewTenant(tenant string) bool {
	if tenant == f.protectedTenant() {
		return true
	}

	f.mu.RLock()
	_, cached := f.keySets[tenant]
	f.mu.RUnlock()
	if cached {
		return true
	}

	f.admissionMu.Lock()
	defer f.admissionMu.Unlock()
	now := time.Now()
	if now.After(f.admissionResetAt) {
		f.admissionCount = 0
		f.admissionResetAt = now.Add(f.admissionWindow)
	}
	if f.admissionCount >= f.admissionLimit {
		return false
	}
	f.admissionCount++
	return true
}

// tenantForContext resolves the effective tenant key to use for both the
// outbound X-Tenant-ID header and the per-tenant cache slot: a per-call
// tenant from ctx if present, otherwise the static, operator-configured
// fallback, otherwise "" (the untenanted default slot). fetch and GetKey
// both call this so they always agree on which tenant a given call is for.
func (f *Fetcher) tenantForContext(ctx context.Context) string {
	if tenantID, ok := ctx.Value(tenantIDContextKey{}).(string); ok && tenantID != "" {
		return tenantID
	}
	return f.configuredTenantID
}

// Start begins background key refresh. Call Stop() to clean up.
func (f *Fetcher) Start(ctx context.Context) {
	ctx, f.cancel = context.WithCancel(ctx)

	// Initial fetch (best-effort).
	_ = f.fetch(ctx)

	go func() {
		ticker := time.NewTicker(f.refresh)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = f.fetch(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop cancels background refresh.
func (f *Fetcher) Stop() {
	if f.cancel != nil {
		f.cancel()
	}
}

// KeySet returns the cached JWKS for the given tenant ("" for the
// untenanted/default slot — see tenantForContext). May be nil if no fetch
// has succeeded for that tenant yet.
func (f *Fetcher) KeySet(tenant string) *jose.JSONWebKeySet {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.keySets[tenant]
}

// GetKey looks up a key by kid, scoped to ctx's effective tenant (see
// tenantForContext). If the kid is not found in that tenant's cache,
// triggers an on-demand refresh for that same tenant and retries once
// (handles key rotation race). A cache hit for one tenant is never
// returned for a lookup resolving to a different tenant.
func (f *Fetcher) GetKey(ctx context.Context, kid string) ([]jose.JSONWebKey, error) {
	tenant := f.tenantForContext(ctx)

	f.mu.RLock()
	ks := f.keySets[tenant]
	f.mu.RUnlock()

	if ks != nil {
		keys := ks.Key(kid)
		if len(keys) > 0 {
			return keys, nil
		}
	}

	// kid not found in this tenant's cache — try a refresh in case of key
	// rotation. fetch resolves the same tenant from ctx, so this refreshes
	// (and re-checks) the same cache slot, never a different tenant's.
	if err := f.fetch(ctx); err != nil {
		return nil, fmt.Errorf("jwks: failed to refresh keys: %w", err)
	}

	f.mu.RLock()
	defer f.mu.RUnlock()
	ks = f.keySets[tenant]
	if ks == nil {
		return nil, fmt.Errorf("jwks: no keys available")
	}
	keys := ks.Key(kid)
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks: key %q not found", kid)
	}
	return keys, nil
}

// fetch retrieves the JWKS from the remote endpoint and stores it in the
// cache slot for ctx's effective tenant (see tenantForContext) — never in
// a single shared slot that a different tenant's lookup could also read.
func (f *Fetcher) fetch(ctx context.Context) error {
	tenant := f.tenantForContext(ctx)

	if !f.admitNewTenant(tenant) {
		return fmt.Errorf("jwks: too many distinct tenants requested keys recently; refusing to fetch for %q", tenant)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return fmt.Errorf("jwks: failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	// tenant is "" for the untenanted case (no per-call tenant and no
	// configuredTenantID) — send no header then, exactly as before.
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return fmt.Errorf("jwks: failed to read response: %w", err)
	}

	var ks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &ks); err != nil {
		return fmt.Errorf("jwks: failed to parse JWKS: %w", err)
	}

	f.mu.Lock()
	f.touchTenantLocked(tenant)
	f.keySets[tenant] = &ks
	f.lastFetch = time.Now()
	f.mu.Unlock()

	return nil
}
