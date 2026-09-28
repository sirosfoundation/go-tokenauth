package validator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-tokenauth/claims"
)

// newTestSigningKey generates an ECDSA key and wraps its public half in a
// JWK, for use in JWKS test servers below.
func newTestSigningKey(t *testing.T) (*ecdsa.PrivateKey, gojose.JSONWebKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := gojose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     "test-kid",
		Algorithm: string(gojose.ES256),
		Use:       "sig",
	}
	return key, jwk
}

func setupASServer(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, jwk := newTestSigningKey(t)
	ks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)
	return ts, key, jwk.KeyID
}

// setupASServerWithTenantCapture is like setupASServer but also records the
// X-Tenant-ID header of the most recent JWKS request into seenTenant, for
// tests that check the routing-tenant behavior.
func setupASServerWithTenantCapture(t *testing.T) (ts *httptest.Server, key *ecdsa.PrivateKey, kid string, seenTenant *string) {
	t.Helper()
	key, jwk := newTestSigningKey(t)
	ks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}}
	seenTenant = new(string)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seenTenant = r.Header.Get("X-Tenant-ID")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)
	return ts, key, jwk.KeyID, seenTenant
}

func issueTestToken(t *testing.T, key *ecdsa.PrivateKey, kid, issuer, audience, tenantID string, tac claims.TAC) string {
	return issueTestTokenWithRoutingTenant(t, key, kid, issuer, audience, tenantID, "", tac)
}

func issueTestTokenWithRoutingTenant(t *testing.T, key *ecdsa.PrivateKey, kid, issuer, audience, tenantID, routingTenant string, tac claims.TAC) string {
	t.Helper()
	sig, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.ES256, Key: key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	cl := claims.AccessTokenClaims{
		Claims: jwt.Claims{
			ID:        "jti-1",
			Issuer:    issuer,
			Subject:   "user-1",
			Audience:  jwt.Audience{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			Expiry:    jwt.NewNumericDate(now.Add(2 * time.Minute)),
		},
		TenantID: tenantID,
		TAC:      tac,
		ACR:      "urn:siros:acr:passkey",
	}

	builder := jwt.Signed(sig).Claims(cl)
	if routingTenant != "" {
		builder = builder.Claims(struct {
			Tenant string `json:"tenant"`
		}{Tenant: routingTenant})
	}

	token, err := builder.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// legacyTokenOpts configures issueLegacyToken. Subject and UserID default to
// "user-1" when unset.
type legacyTokenOpts struct {
	jti      string
	issuer   string
	audience string
	did      string
	tenantID string
}

// issueLegacyToken signs a legacy HMAC token with the given secret and
// claims, cutting down on the boilerplate repeated across the legacy
// validation tests below.
func issueLegacyToken(t *testing.T, secret []byte, opts legacyTokenOpts) string {
	t.Helper()
	now := time.Now()
	lc := &LegacyTokenClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			ID:        opts.jti,
			Issuer:    opts.issuer,
			Subject:   "user-1",
			Audience:  gojwt.ClaimStrings{opts.audience},
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(time.Hour)),
		},
		UserID:   "user-1",
		DID:      opts.did,
		TenantID: opts.tenantID,
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, lc)
	raw, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestValidator_Asymmetric_Success(t *testing.T) {
	ts, key, kid := setupASServer(t)
	ctx := context.Background()

	v := New(Config{
		JWKSURL:   ts.URL,
		Issuer:    "test-issuer",
		Audiences: []string{"api"},
	})
	v.Start(ctx)
	defer v.Stop()

	token := issueTestToken(t, key, kid, "test-issuer", "api", "tenant-1", claims.TAC("rl"))

	result, err := v.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if result.UserID != "user-1" {
		t.Errorf("expected user-1, got %s", result.UserID)
	}
	if result.TenantID != "tenant-1" {
		t.Errorf("expected tenant-1, got %s", result.TenantID)
	}
	if result.TAC != claims.TAC("rl") {
		t.Errorf("expected TAC rl, got %s", result.TAC)
	}
	if result.Mode != claims.ModeSession {
		t.Errorf("expected mode session, got %s", result.Mode)
	}
	if len(result.Audience) != 1 || result.Audience[0] != "api" {
		t.Errorf("expected Audience [api], got %v", result.Audience)
	}
}

func TestValidator_Asymmetric_WrongIssuer(t *testing.T) {
	ts, key, kid := setupASServer(t)
	ctx := context.Background()

	v := New(Config{
		JWKSURL:   ts.URL,
		Issuer:    "expected-issuer",
		Audiences: []string{"api"},
	})
	v.Start(ctx)
	defer v.Stop()

	token := issueTestToken(t, key, kid, "wrong-issuer", "api", "tenant-1", claims.TAC("rl"))

	_, err := v.Validate(ctx, token)
	if err == nil {
		t.Error("expected error for wrong issuer")
	}
}

func TestValidator_Asymmetric_WrongAudience(t *testing.T) {
	ts, key, kid := setupASServer(t)
	ctx := context.Background()

	v := New(Config{
		JWKSURL:   ts.URL,
		Issuer:    "test-issuer",
		Audiences: []string{"api"},
	})
	v.Start(ctx)
	defer v.Stop()

	token := issueTestToken(t, key, kid, "test-issuer", "other-api", "tenant-1", claims.TAC("rl"))

	_, err := v.Validate(ctx, token)
	if err == nil {
		t.Error("expected error for wrong audience")
	}
}

// TestValidator_Asymmetric_FirstOfSeveralAudiences proves that a token
// bearing only the FIRST of several configured audiences validates
// successfully. Regression test for the "last-wins" bug: golang-jwt v5's
// WithAudience(...) is variadic but REPLACES the parser's expected-audience
// set on each call, so building parser options with one WithAudience call
// per configured audience (in a loop) silently dropped every audience but
// the last that was appended. A token carrying only the first-configured
// audience would then be falsely rejected. The asymmetric path uses
// go-jose's jwt.Expected.AnyAudience directly (not golang-jwt's parser
// options) but is exercised here too for parity with the legacy path.
func TestValidator_Asymmetric_FirstOfSeveralAudiences(t *testing.T) {
	ts, key, kid := setupASServer(t)
	ctx := context.Background()

	v := New(Config{
		JWKSURL:   ts.URL,
		Issuer:    "test-issuer",
		Audiences: []string{"first-api", "second-api", "third-api"},
	})
	v.Start(ctx)
	defer v.Stop()

	token := issueTestToken(t, key, kid, "test-issuer", "first-api", "tenant-1", claims.TAC("rl"))

	result, err := v.Validate(ctx, token)
	if err != nil {
		t.Fatalf("expected token with first-configured audience to validate, got error: %v", err)
	}
	if len(result.Audience) != 1 || result.Audience[0] != "first-api" {
		t.Errorf("expected Audience [first-api], got %v", result.Audience)
	}
}

// TestValidator_Legacy_FirstOfSeveralAudiences is the legacy-path
// counterpart of TestValidator_Asymmetric_FirstOfSeveralAudiences. The
// legacy path is the one that built golang-jwt v5 ParserOptions in a loop
// and is where the last-wins bug actually lived.
func TestValidator_Legacy_FirstOfSeveralAudiences(t *testing.T) {
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	ctx := context.Background()

	v := New(Config{
		Issuer:    "legacy-issuer",
		Audiences: []string{"first-api", "second-api", "third-api"},
		Legacy: LegacyConfig{
			Enabled:    true,
			HMACSecret: secret,
			Issuers:    []string{"legacy-issuer"},
		},
	})

	raw := issueLegacyToken(t, secret, legacyTokenOpts{
		jti:      "jti-legacy-first-aud",
		issuer:   "legacy-issuer",
		audience: "first-api",
	})

	result, err := v.Validate(ctx, raw)
	if err != nil {
		t.Fatalf("expected legacy token with first-configured audience to validate, got error: %v", err)
	}
	if len(result.Audience) != 1 || result.Audience[0] != "first-api" {
		t.Errorf("expected Audience [first-api], got %v", result.Audience)
	}
}

// TestValidator_Legacy_SecondOfSeveralIssuersAccepted is a regression test
// for a Copilot-review finding on this PR: gojwt.WithIssuer only supports a
// single exact issuer and enforces it inside ParseWithClaims itself, so
// passing it as a parser option (checking only issuers[0]) hard-rejected any
// token using an accepted issuer other than the first, before the manual
// multi-issuer membership check ever ran. A token signed by the SECOND of
// several configured legacy issuers must still validate successfully.
func TestValidator_Legacy_SecondOfSeveralIssuersAccepted(t *testing.T) {
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	ctx := context.Background()

	v := New(Config{
		Audiences: []string{"api"},
		Legacy: LegacyConfig{
			Enabled:    true,
			HMACSecret: secret,
			Issuers:    []string{"legacy-issuer-1", "legacy-issuer-2"},
		},
	})

	raw := issueLegacyToken(t, secret, legacyTokenOpts{
		jti:      "jti-legacy-second-issuer",
		issuer:   "legacy-issuer-2",
		audience: "api",
	})

	if _, err := v.Validate(ctx, raw); err != nil {
		t.Fatalf("expected legacy token using the second-configured issuer to validate, got error: %v", err)
	}
}

// TestValidator_Legacy_WrongIssuerRejected proves a legacy token with an
// issuer outside the accepted set is rejected, and specifically that
// Legacy.Issuers is actually consulted when only the shared top-level
// Config.Issuer would otherwise be set.
func TestValidator_Legacy_WrongIssuerRejected(t *testing.T) {
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	ctx := context.Background()

	v := New(Config{
		Issuer:    "legacy-issuer",
		Audiences: []string{"api"},
		Legacy: LegacyConfig{
			Enabled:    true,
			HMACSecret: secret,
			Issuers:    []string{"legacy-issuer"},
		},
	})

	raw := issueLegacyToken(t, secret, legacyTokenOpts{
		jti:      "jti-legacy-bad-iss",
		issuer:   "attacker-issuer",
		audience: "api",
	})

	if _, err := v.Validate(ctx, raw); err == nil {
		t.Error("expected error for legacy token with unaccepted issuer")
	}
}

// TestValidator_Legacy_IssuerFallsBackToSharedIssuer proves that when a
// caller only sets the shared Config.Issuer (not Legacy.Issuers), legacy
// tokens still get an issuer check rather than none at all. This was the
// "Legacy.Issuers is never populated by any caller path" gap: real callers
// commonly set only Config.Issuer, expecting it to apply to both token
// kinds.
func TestValidator_Legacy_IssuerFallsBackToSharedIssuer(t *testing.T) {
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	ctx := context.Background()

	v := New(Config{
		Issuer:    "shared-issuer",
		Audiences: []string{"api"},
		Legacy: LegacyConfig{
			Enabled:    true,
			HMACSecret: secret,
			// Issuers deliberately left unset.
		},
	})

	rawBad := issueLegacyToken(t, secret, legacyTokenOpts{
		jti:      "jti-legacy-fallback-bad",
		issuer:   "attacker-issuer",
		audience: "api",
	})
	if _, err := v.Validate(ctx, rawBad); err == nil {
		t.Error("expected error for legacy token whose issuer doesn't match the shared Config.Issuer fallback")
	}

	rawGood := issueLegacyToken(t, secret, legacyTokenOpts{
		jti:      "jti-legacy-fallback-good",
		issuer:   "shared-issuer",
		audience: "api",
	})
	if _, err := v.Validate(ctx, rawGood); err != nil {
		t.Fatalf("expected legacy token matching the shared Config.Issuer fallback to validate, got: %v", err)
	}
}

// TestValidator_Asymmetric_EmptyAudiencesIsConfigError proves that an
// empty/unset Audiences list is treated as a configuration error and fails
// closed, rather than silently disabling audience enforcement.
func TestValidator_Asymmetric_EmptyAudiencesIsConfigError(t *testing.T) {
	ts, key, kid := setupASServer(t)
	ctx := context.Background()

	v := New(Config{
		JWKSURL: ts.URL,
		Issuer:  "test-issuer",
		// Audiences deliberately left empty.
	})
	v.Start(ctx)
	defer v.Stop()

	token := issueTestToken(t, key, kid, "test-issuer", "anything-goes", "tenant-1", claims.TAC("rl"))

	if _, err := v.Validate(ctx, token); err == nil {
		t.Error("expected error when no audiences are configured, got nil (fail-open)")
	}
}

// TestValidator_Legacy_EmptyAudiencesIsConfigError is the legacy-path
// counterpart of TestValidator_Asymmetric_EmptyAudiencesIsConfigError.
func TestValidator_Legacy_EmptyAudiencesIsConfigError(t *testing.T) {
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	ctx := context.Background()

	v := New(Config{
		Issuer: "legacy-issuer",
		// Audiences deliberately left empty.
		Legacy: LegacyConfig{
			Enabled:    true,
			HMACSecret: secret,
			Issuers:    []string{"legacy-issuer"},
		},
	})

	raw := issueLegacyToken(t, secret, legacyTokenOpts{
		jti:      "jti-legacy-no-aud-cfg",
		issuer:   "legacy-issuer",
		audience: "anything-goes",
	})

	if _, err := v.Validate(ctx, raw); err == nil {
		t.Error("expected error when no audiences are configured, got nil (fail-open)")
	}
}

func TestValidator_Legacy_Success(t *testing.T) {
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	ctx := context.Background()

	v := New(Config{
		Issuer:    "legacy-issuer",
		Audiences: []string{"api"},
		Legacy: LegacyConfig{
			Enabled:    true,
			HMACSecret: secret,
			Issuers:    []string{"legacy-issuer"},
		},
	})

	raw := issueLegacyToken(t, secret, legacyTokenOpts{
		jti:      "jti-legacy",
		issuer:   "legacy-issuer",
		audience: "api",
		did:      "did:example:123",
		tenantID: "tenant-1",
	})

	result, err := v.Validate(ctx, raw)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if result.UserID != "user-1" {
		t.Errorf("expected user-1, got %s", result.UserID)
	}
	if result.DID != "did:example:123" {
		t.Errorf("expected DID did:example:123, got %s", result.DID)
	}
	if result.Mode != claims.ModeLegacy {
		t.Errorf("expected mode legacy, got %s", result.Mode)
	}
	if len(result.Audience) != 1 || result.Audience[0] != "api" {
		t.Errorf("expected Audience [api], got %v", result.Audience)
	}
}

func TestValidator_Legacy_Disabled(t *testing.T) {
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	ctx := context.Background()

	v := New(Config{
		Legacy: LegacyConfig{
			Enabled: false,
		},
	})

	lc := &LegacyTokenClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, lc)
	raw, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Validate(ctx, raw)
	if err == nil {
		t.Error("expected error when legacy is disabled")
	}
}

// mockRevocationChecker is a test implementation of revocation.Checker.
type mockRevocationChecker struct {
	revoked map[string]bool
}

func (m *mockRevocationChecker) IsRevoked(_ context.Context, jti string) bool {
	return m.revoked[jti]
}

func TestValidator_Asymmetric_Revoked(t *testing.T) {
	ts, key, kid := setupASServer(t)
	ctx := context.Background()

	checker := &mockRevocationChecker{revoked: map[string]bool{"jti-1": true}}

	v := New(Config{
		JWKSURL:    ts.URL,
		Issuer:     "test-issuer",
		Audiences:  []string{"api"},
		Revocation: checker,
	})
	v.Start(ctx)
	defer v.Stop()

	token := issueTestToken(t, key, kid, "test-issuer", "api", "tenant-1", claims.TAC("rl"))

	_, err := v.Validate(ctx, token)
	if err == nil {
		t.Error("expected error for revoked token")
	}
}

func TestValidator_Asymmetric_SendsTenantHeaderForIssuerRequests(t *testing.T) {
	ts, key, kid, seenTenant := setupASServerWithTenantCapture(t)

	v := New(Config{
		JWKSURL:   ts.URL,
		Issuer:    "test-issuer",
		Audiences: []string{"api"},
	})

	token := issueTestTokenWithRoutingTenant(t, key, kid, "test-issuer", "api", "tenant-id-1", "tenant-1", claims.TAC("rl"))
	if _, err := v.Validate(context.Background(), token); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if *seenTenant != "tenant-1" {
		t.Fatalf("expected X-Tenant-ID tenant-1, got %q", *seenTenant)
	}
}

func TestValidator_Asymmetric_IgnoresInvalidRoutingTenant(t *testing.T) {
	ts, key, kid, seenTenant := setupASServerWithTenantCapture(t)

	v := New(Config{
		JWKSURL:   ts.URL,
		Issuer:    "test-issuer",
		Audiences: []string{"api"},
	})

	token := issueTestTokenWithRoutingTenant(t, key, kid, "test-issuer", "api", "tenant-1", "Tenant_1", claims.TAC("rl"))
	if _, err := v.Validate(context.Background(), token); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if *seenTenant != "" {
		t.Fatalf("expected no X-Tenant-ID header for invalid tenant, got %q", *seenTenant)
	}
}
