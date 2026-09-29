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
// maxNewTenantFetchesPerWindow/newTenantFetchWindow (see touchTenantLocked)
// bound that separately, by rate-limiting fetches for tenants not already
// cached.
const maxCachedTenants = 256

// maxNewTenantFetchesPerWindow and newTenantFetchWindow bound how many
// previously-uncached tenants may trigger an outbound JWKS fetch within a
// given window (see touchTenantLocked). Already-cached tenants and the
// operator-configured tenant (see protectedTenant) are exempt and never
// count against this limit.
const (
	maxNewTenantFetchesPerWindow = 64
	newTenantFetchWindow         = time.Second
)

// defaultMinFetchInterval bounds how often a fetch may be re-attempted for
// the SAME tenant slot, independent of admission/eviction exemptions (see
// touchTenantLocked). touchTenantLocked only gates a tenant's first-ever (or
// evicted-and-returning) admission; it says nothing about how often a
// GetKey cache miss re-triggers a fetch for a tenant that's already
// admitted (cached, or the fallback/protected slot). The JWT's kid header
// is itself unverified and attacker-controlled, so an attacker who already
// has (or is exempt from) tenant admission can still send arbitrarily many
// distinct, nonexistent kid values to force a fresh outbound fetch on
// every single request. This cooldown bounds that independently of any
// exemption: no tenant slot, including the protected/fallback one, may be
// refetched more than once per defaultMinFetchInterval.
const defaultMinFetchInterval = time.Second

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
	// inFlightFetches coalesces concurrent fetch calls for the SAME
	// tenant: only the first caller for a given tenant actually runs
	// admission/cooldown and the network round-trip; concurrent callers
	// for that tenant wait on its channel instead of independently
	// risking minFetchInterval throttling and returning a spurious error
	// for a request the in-flight fetch was about to satisfy anyway (see
	// fetch). Keyed and cleaned up per tenant, so its size is bounded by
	// however many distinct tenants have a fetch genuinely in flight at
	// once — inherently small and short-lived, not a new unbounded-growth
	// vector on top of the existing admission/cache bounds.
	inFlightFetches map[string]chan struct{}
	// lru and lruElems bound keySets to maxCachedTenants entries (see its
	// doc comment): lru's front is the most-recently-fetched tenant, back
	// is the least-recently-fetched and the next to be evicted.
	lru      *list.List
	lruElems map[string]*list.Element
	// cacheCapacity defaults to maxCachedTenants; only overridden by tests
	// to exercise eviction without a large number of fetches.
	cacheCapacity int
	// minFetchInterval defaults to defaultMinFetchInterval; only overridden
	// by tests to exercise throttling deterministically and quickly.
	minFetchInterval time.Duration
	lastFetch        time.Time
	cancel           context.CancelFunc

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

	// admissionCount and admissionResetAt implement the new-tenant fetch
	// rate limiter described at maxNewTenantFetchesPerWindow.
	// admissionLimit/admissionWindow default to those constants; only
	// overridden by tests for determinism. All four are read and written
	// only from touchTenantLocked, under f.mu (write lock) — folded into
	// the same critical section as eviction/creation so that "is this
	// tenant currently cached" and "admit/evict/create" happen atomically
	// with respect to each other (an earlier, two-step version of this
	// check read the cache under a separate, released lock, letting a
	// concurrent eviction slip a re-admission through without charging
	// the budget).
	admissionCount   int
	admissionResetAt time.Time
	admissionLimit   int
	admissionWindow  time.Duration

	// nextGeneration is a Fetcher-wide, monotonically increasing counter.
	// Each admitted fetch attempt (see touchTenantLocked) gets the next
	// value, unique across this Fetcher's entire lifetime — including
	// across a tenant's eviction and later re-admission. A per-slot
	// counter that reset to 1 on every re-admission could coincide with a
	// still-in-flight, pre-eviction fetch's generation, letting
	// commitFetchResultLocked mistake a stale response for current.
	nextGeneration uint64
}

type tenantIDContextKey struct{}

// ContextWithTenantID attaches a tenant ID to ctx for issuer-bound requests.
func ContextWithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDContextKey{}, tenantID)
}

type internalRefreshContextKey struct{}

// internalRefreshContext marks ctx as Start's own internal background
// refresh — never set by, or reachable from, any external request. "ctx
// carries no explicit tenant claim" is true both for a genuine internal
// refresh AND for an ordinary per-call request whose token simply has no
// tenant/tenant_id claim (or an invalidated one); those are NOT the same
// trust level, so tenantForContext checks for this marker explicitly
// rather than treating "no claim" alone as license to use
// configuredTenantID. Only Start applies this marker (see its use there).
func internalRefreshContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, internalRefreshContextKey{}, true)
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
		inFlightFetches:    make(map[string]chan struct{}),
		lru:                list.New(),
		lruElems:           make(map[string]*list.Element),
		cacheCapacity:      maxCachedTenants,
		minFetchInterval:   defaultMinFetchInterval,
		configuredTenantID: configuredTenantID,
		admissionLimit:     maxNewTenantFetchesPerWindow,
		admissionWindow:    newTenantFetchWindow,
	}
}

// tenantLRUEntry is the value stored in each Fetcher.lru node.
//
// protected starts false unless the entry is FIRST created by a fetch
// whose tenant came from the static fallback path (viaFallback — see
// tenantForContext), never by an explicit per-call claim, so an attacker
// sending an explicit claim that happens to equal the configured tenant's
// string cannot manufacture eviction-protected status merely by creating
// the slot first. A later touchTenantLocked call for the SAME tenant
// string does upgrade protected to true if THAT call is itself
// viaFallback — so a slot an attacker's spoofed claim created first still
// ends up correctly protected once a genuine fallback fetch subsequently
// claims the same tenant string. protected is never downgraded once set.
//
// lastAttempt records when a fetch was last attempted for this tenant
// (successful or not), enforcing minFetchInterval between attempts
// regardless of protected/admission status — see defaultMinFetchInterval.
//
// incarnation identifies THIS creation of the slot: it's assigned once,
// when the slot is created (whether that's truly the first time, or a
// fresh re-admission after eviction), and never changes for as long as
// this incarnation of the slot exists. Eviction followed by re-admission
// always produces a brand-new incarnation (drawn from the Fetcher-wide
// nextGeneration counter, which never resets), so a response captured
// under a previous incarnation can never be mistaken for current — see
// commitFetchResultLocked.
//
// committed is the seq (see fetchAttempt) of the most recently
// SUCCESSFULLY COMMITTED response for this incarnation, not merely the
// most recently ATTEMPTED one — 0 means nothing has committed yet. This
// distinction matters: fetch's HTTP round-trip runs without holding f.mu,
// so a slower attempt can still be in flight when a later attempt for the
// same tenant is admitted. If the later attempt then fails (network
// error, non-200, etc.), it never calls commitFetchResultLocked at all,
// so it must not be able to block the earlier, slower attempt's
// eventual success from committing — only an attempt whose response has
// actually landed should be able to supersede an older one.
type tenantLRUEntry struct {
	tenant      string
	protected   bool
	lastAttempt time.Time
	incarnation uint64
	committed   uint64
}

// fetchAttempt identifies one admitted fetch attempt for commitFetchResultLocked.
type fetchAttempt struct {
	incarnation uint64
	seq         uint64
}

// touchTenantLocked records an attempt to fetch tenant right now,
// combining LRU/eviction bookkeeping with new-tenant admission control in
// one critical section. An earlier, two-step version of this check read
// "is this tenant cached" via a separate, released lock before this
// function ran; a concurrent eviction could slip in between the two
// steps, letting a re-admission through without ever charging the
// admission budget. Folding both decisions into this single call under
// f.mu (write lock) closes that gap: "is this tenant currently cached",
// "does it need to consume the new-tenant admission budget", and
// "evict/create its slot" are now all decided atomically.
//
// For an existing entry: enforces minFetchInterval since that tenant's
// last attempt (returning allowed=false, without updating anything, if
// attempted too soon) and upgrades protected to true if this attempt is
// viaFallback. For a brand-new (or evicted-and-returning) tenant: the
// fallback/protected tenant (viaFallback) is always admitted; any other
// new tenant is subject to admissionLimit/admissionWindow, so an attacker
// cycling through many distinct unverified tenant claims cannot generate
// unbounded outbound requests or repeatedly evict legitimate entries by
// forcing constant churn. An admitted new tenant's slot is created
// (lastAttempt = now, protected = viaFallback), evicting the
// least-recently-attempted non-protected entry first if the cache is
// already at cacheCapacity — or, if every existing entry is protected and
// so nothing is evictable, rejecting this admission outright (rolling
// back the admission-budget charge above, if any) rather than letting the
// cache silently grow past cacheCapacity.
//
// Caller must hold f.mu (write lock). allowed reports whether the attempt
// may proceed to the network — fetch must not do so if it's false.
// attempt must be passed back to commitFetchResultLocked unchanged.
func (f *Fetcher) touchTenantLocked(tenant string, viaFallback bool) (allowed bool, attempt fetchAttempt) {
	now := time.Now()

	if el, ok := f.lruElems[tenant]; ok {
		entry, _ := el.Value.(tenantLRUEntry) // always this type: only touchTenantLocked pushes onto lru
		// Apply the protected upgrade unconditionally, even if this
		// attempt turns out to be throttled below: a genuine fallback
		// call must still be able to mark an existing (e.g.
		// spoofed-claim-created) slot as protected without needing to
		// reach the network. Deferring this past the throttle check would
		// let a slot the fallback path hasn't yet had an UNTHROTTLED
		// chance to touch remain evictable indefinitely under sustained
		// churn.
		if viaFallback {
			entry.protected = true
		}
		throttled := now.Sub(entry.lastAttempt) < f.minFetchInterval
		if !throttled {
			f.nextGeneration++
			entry.lastAttempt = now
		}
		el.Value = entry
		if throttled {
			return false, fetchAttempt{}
		}
		f.lru.MoveToFront(el)
		return true, fetchAttempt{incarnation: entry.incarnation, seq: f.nextGeneration}
	}

	// Not currently cached: a genuinely new (or evicted-and-returning)
	// tenant admission. viaFallback (never a string match — see
	// tenantForContext) is what exempts a call from the limiter, so an
	// attacker cannot bypass it merely by guessing or copying the
	// configured tenant's value.
	chargedAdmission := false
	if !viaFallback {
		if now.After(f.admissionResetAt) {
			f.admissionCount = 0
			f.admissionResetAt = now.Add(f.admissionWindow)
		}
		if f.admissionCount >= f.admissionLimit {
			return false, fetchAttempt{}
		}
		f.admissionCount++
		chargedAdmission = true
	}

	if f.lru.Len() >= f.cacheCapacity {
		evicted := false
		for oldest := f.lru.Back(); oldest != nil; oldest = oldest.Prev() {
			entry, _ := oldest.Value.(tenantLRUEntry)
			if entry.protected {
				continue // never evict a slot protected by a genuine fallback fetch
			}
			f.lru.Remove(oldest)
			delete(f.lruElems, entry.tenant)
			delete(f.keySets, entry.tenant)
			evicted = true
			break
		}
		if !evicted {
			// Every existing entry is protected (only possible with
			// cacheCapacity == 1 and a configured tenant): there is
			// nothing to evict, so reject this admission rather than
			// grow the cache past cacheCapacity.
			if chargedAdmission {
				f.admissionCount--
			}
			return false, fetchAttempt{}
		}
	}
	f.nextGeneration++
	incarnation := f.nextGeneration
	f.nextGeneration++
	seq := f.nextGeneration
	entry := tenantLRUEntry{tenant: tenant, protected: viaFallback, lastAttempt: now, incarnation: incarnation}
	f.lruElems[tenant] = f.lru.PushFront(entry)
	return true, fetchAttempt{incarnation: incarnation, seq: seq}
}

// commitFetchResultLocked stores ks for tenant only if attempt.incarnation
// still matches the tenant's current slot (i.e. it hasn't been evicted and
// re-created since this attempt was admitted — see tenantLRUEntry) AND no
// attempt with a higher seq has already committed for this same
// incarnation. A stale response (slot gone, different incarnation, or
// superseded by an already-committed newer attempt) is silently discarded
// rather than resurrecting an evicted entry, crossing into a different
// incarnation of the same tenant string, or overwriting fresher committed
// keys with older ones. Crucially, this compares against the last
// COMMITTED seq, not the last ATTEMPTED one: an attempt that was admitted
// but never successfully committed (e.g. its HTTP request failed) must
// not be able to block an older, slower attempt's eventual success.
// Caller must hold f.mu (write lock).
func (f *Fetcher) commitFetchResultLocked(tenant string, attempt fetchAttempt, ks *jose.JSONWebKeySet) {
	el, ok := f.lruElems[tenant]
	if !ok {
		return // slot was evicted before this response arrived — discard
	}
	entry, _ := el.Value.(tenantLRUEntry)
	if entry.incarnation != attempt.incarnation {
		return // this tenant slot has since been evicted and re-created — discard
	}
	if entry.committed >= attempt.seq {
		return // a newer attempt already committed for this incarnation — discard
	}
	entry.committed = attempt.seq
	el.Value = entry
	f.keySets[tenant] = ks
	f.lastFetch = time.Now()
}

// tenantForContext resolves the effective tenant key to use for both the
// outbound X-Tenant-ID header and the per-tenant cache slot: a per-call
// tenant from ctx if present; otherwise the static, operator-configured
// fallback IF ctx is a genuine internal-refresh call (see
// internalRefreshContext); otherwise "" (the untenanted default slot,
// used by ordinary per-call requests whose token carries no tenant claim
// at all). fetch and GetKey both call this so they always agree on which
// tenant a given call is for.
//
// An ordinary request with no tenant claim resolving to configuredTenantID
// would be wrong: Config.TenantID exists solely to keep Start's background
// refresh warm for one known, operator-chosen tenant, not to silently
// reroute real, tenantless request-driven lookups to it — that could
// select the wrong tenant's keys for validation. Distinguishing "no claim"
// from "genuine internal refresh" is exactly what prevents that: only
// Start's own calls carry the internalRefreshContext marker.
//
// viaFallback reports whether tenant came from that static, internal-only
// fallback — never because an explicit per-call claim happened to equal
// that same string, and never merely because a request lacked a tenant
// claim. This distinction matters: only the fallback path is trusted,
// operator-configured provenance (see touchTenantLocked and
// touchTenantLocked's protected flag); an attacker's own claim (or an
// ordinary request's absent claim) must never be able to buy the same
// trust.
func (f *Fetcher) tenantForContext(ctx context.Context) (tenant string, viaFallback bool) {
	if tenantID, ok := ctx.Value(tenantIDContextKey{}).(string); ok && tenantID != "" {
		return tenantID, false
	}
	if isInternalRefresh, _ := ctx.Value(internalRefreshContextKey{}).(bool); isInternalRefresh {
		return f.configuredTenantID, true
	}
	return "", false
}

// Start begins background key refresh. Call Stop() to clean up.
func (f *Fetcher) Start(ctx context.Context) {
	ctx, f.cancel = context.WithCancel(ctx)
	refreshCtx := internalRefreshContext(ctx)

	// Initial fetch (best-effort).
	_ = f.fetch(refreshCtx)

	go func() {
		ticker := time.NewTicker(f.refresh)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = f.fetch(refreshCtx)
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
	tenant, _ := f.tenantForContext(ctx)

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

// fetch retrieves the JWKS from the remote endpoint for ctx's effective
// tenant (see tenantForContext) and stores it in that tenant's cache
// slot — never in a single shared slot that a different tenant's lookup
// could also read.
//
// Concurrent calls for the SAME tenant are coalesced: only the first
// caller for a given tenant actually runs admission/cooldown and the
// network round-trip; any other caller for that same tenant that arrives
// while one is already in flight simply waits for it to finish and
// returns nil, leaving GetKey's own post-fetch cache check to determine
// the outcome. Without this, a burst of concurrent cache-miss lookups for
// the same tenant (e.g. right after a cold start or a key rotation) would
// have every caller but the first independently hit minFetchInterval's
// cooldown and fail outright, even though the first caller's in-flight
// fetch was about to satisfy all of them.
func (f *Fetcher) fetch(ctx context.Context) error {
	tenant, viaFallback := f.tenantForContext(ctx)

	f.mu.Lock()
	if ch, inFlight := f.inFlightFetches[tenant]; inFlight {
		// Preserve fallback provenance even when joining a fetch that a
		// non-fallback caller already started: a genuine fallback call
		// (e.g. Start's ticker) must still be able to mark this slot
		// protected, even though it isn't the one doing admission or the
		// network round-trip this time. The leader's own call to
		// touchTenantLocked (which created this entry, if it exists at
		// all) has already returned by the time any follower can observe
		// inFlight == true — both happen under this same lock — so it's
		// safe to look the entry up here directly.
		if viaFallback {
			if el, ok := f.lruElems[tenant]; ok {
				entry, _ := el.Value.(tenantLRUEntry)
				entry.protected = true
				el.Value = entry
			}
		}
		f.mu.Unlock()
		select {
		case <-ch:
			return nil // the in-flight fetch has completed; caller re-checks the cache itself
		case <-ctx.Done():
			// Honor the follower's own context: without this, a canceled
			// request handler would block until an unrelated, possibly
			// slow or stalled leader fetch finishes, letting goroutines
			// accumulate and defeating request deadlines.
			return ctx.Err()
		}
	}
	ch := make(chan struct{})
	f.inFlightFetches[tenant] = ch
	// touchTenantLocked decides both new-tenant admission and the
	// minFetchInterval refetch cooldown in one atomic step (see its doc
	// comment for why that matters) — bounding both tenant cardinality
	// and, independently, how often any single tenant slot may be
	// refetched at all.
	allowed, attempt := f.touchTenantLocked(tenant, viaFallback)
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		delete(f.inFlightFetches, tenant)
		f.mu.Unlock()
		close(ch)
	}()

	if !allowed {
		return fmt.Errorf("jwks: refusing to fetch for tenant %q (rate-limited or attempted too soon)", tenant)
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
	f.commitFetchResultLocked(tenant, attempt, &ks)
	f.mu.Unlock()

	return nil
}
