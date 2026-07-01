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

func setupASServer(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey, string) {
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
	ks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(ts.Close)
	return ts, key, "test-kid"
}

func issueTestToken(t *testing.T, key *ecdsa.PrivateKey, kid, issuer, audience, tenantID string, tac claims.TAC) string {
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

	token, err := jwt.Signed(sig).Claims(cl).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
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

	now := time.Now()
	lc := &LegacyTokenClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			ID:        "jti-legacy",
			Issuer:    "legacy-issuer",
			Subject:   "user-1",
			Audience:  gojwt.ClaimStrings{"api"},
			IssuedAt:  gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(time.Hour)),
		},
		UserID:   "user-1",
		DID:      "did:example:123",
		TenantID: "tenant-1",
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, lc)
	raw, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}

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
