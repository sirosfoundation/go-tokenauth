package tokengin

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

	"github.com/gin-gonic/gin"
	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"
)

func setupMiddleware(t *testing.T) (*gin.Engine, *ecdsa.PrivateKey, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := gojose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     "mw-kid",
		Algorithm: string(gojose.ES256),
		Use:       "sig",
	}
	ks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ks)
	}))
	t.Cleanup(jwksServer.Close)

	v := validator.New(validator.Config{
		JWKSURL:   jwksServer.URL,
		Issuer:    "test-issuer",
		Audiences: []string{"api"},
	})
	v.Start(context.Background())
	t.Cleanup(v.Stop)

	router := gin.New()
	router.GET("/protected", TokenAuth(v), func(c *gin.Context) {
		result, _ := GetResult(c)
		c.JSON(http.StatusOK, gin.H{
			"user_id":   result.UserID,
			"tenant_id": result.TenantID,
			"tac":       string(result.TAC),
			"mode":      string(result.Mode),
		})
	})
	router.GET("/write-only", TokenAuth(v), MustHaveTAC("w"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	return router, key, "mw-kid"
}

func issueToken(t *testing.T, key *ecdsa.PrivateKey, kid, issuer, audience, tenantID string, tac claims.TAC) string {
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
			ID:        "jti-mw",
			Issuer:    issuer,
			Subject:   "user-1",
			Audience:  jwt.Audience{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			Expiry:    jwt.NewNumericDate(now.Add(2 * time.Minute)),
		},
		TenantID: tenantID,
		TAC:      tac,
	}

	token, err := jwt.Signed(sig).Claims(cl).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestTokenAuth_Success(t *testing.T) {
	router, key, kid := setupMiddleware(t)
	token := issueToken(t, key, kid, "test-issuer", "api", "tenant-1", claims.TAC("rwl"))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenAuth_NoToken(t *testing.T) {
	router, _, _ := setupMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	// RFC 6750 §3: no bearer token was even presented, so the challenge
	// is invalid_request, not invalid_token.
	if want, got := `Bearer error="invalid_request"`, w.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	// The pre-existing body must not change — existing consumers may
	// already match on it.
	if got := body["error"]; got != "missing authorization token" {
		t.Errorf(`body["error"] = %q, want "missing authorization token"`, got)
	}
}

// A Bearer scheme followed only by whitespace presents no credential, so
// it gets the invalid_request challenge, not invalid_token.
func TestTokenAuth_WhitespaceOnlyToken(t *testing.T) {
	router, _, _ := setupMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer    ")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if want, got := `Bearer error="invalid_request"`, w.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestTokenAuth_InvalidToken(t *testing.T) {
	router, _, _ := setupMiddleware(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if want, got := `Bearer error="invalid_token", error_description="the access token is invalid"`, w.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	// The existing "error" field/value must not change — existing
	// consumers (e.g. go-wallet-backend) may already match on it.
	if got := body["error"]; got != "invalid token" {
		t.Errorf(`body["error"] = %q, want "invalid token"`, got)
	}
	if got := body["error_description"]; got != "the access token is invalid" {
		t.Errorf(`body["error_description"] = %q, want "the access token is invalid"`, got)
	}
}

func TestTokenAuth_ExpiredToken(t *testing.T) {
	router, key, kid := setupMiddleware(t)

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
			ID:       "jti-mw-expired",
			Issuer:   "test-issuer",
			Subject:  "user-1",
			Audience: jwt.Audience{"api"},
			IssuedAt: jwt.NewNumericDate(now.Add(-time.Hour)),
			Expiry:   jwt.NewNumericDate(now.Add(-time.Minute)),
		},
		TenantID: "tenant-1",
		TAC:      claims.TAC("rwl"),
	}
	token, err := jwt.Signed(sig).Claims(cl).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if want, got := `Bearer error="invalid_token", error_description="the access token expired"`, w.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got := body["error"]; got != "invalid token" {
		t.Errorf(`body["error"] = %q, want "invalid token"`, got)
	}
	if got := body["error_description"]; got != "the access token expired" {
		t.Errorf(`body["error_description"] = %q, want "the access token expired"`, got)
	}
}

// TestTokenAuth_ExpiredLegacyToken covers the golang-jwt expiry sentinel:
// legacy HS256 validation wraps golangjwt.ErrTokenExpired, a different
// error from the go-jose ErrExpired the asymmetric path produces.
func TestTokenAuth_ExpiredLegacyToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := []byte("0123456789abcdef0123456789abcdef")

	v := validator.New(validator.Config{
		Audiences: []string{"api"},
		Legacy: validator.LegacyConfig{
			Enabled:    true,
			HMACSecret: secret,
			Issuers:    []string{"test-issuer"},
		},
	})
	router := gin.New()
	router.GET("/protected", TokenAuth(v), func(c *gin.Context) { c.Status(http.StatusOK) })

	now := time.Now()
	token, err := gojwt.NewWithClaims(gojwt.SigningMethodHS256, validator.LegacyTokenClaims{
		RegisteredClaims: gojwt.RegisteredClaims{
			ID:        "jti-legacy-expired",
			Issuer:    "test-issuer",
			Audience:  gojwt.ClaimStrings{"api"},
			IssuedAt:  gojwt.NewNumericDate(now.Add(-time.Hour)),
			ExpiresAt: gojwt.NewNumericDate(now.Add(-time.Minute)),
		},
		UserID:   "user-1",
		TenantID: "tenant-1",
	}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if want, got := `Bearer error="invalid_token", error_description="the access token expired"`, w.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestMustHaveTAC_Allowed(t *testing.T) {
	router, key, kid := setupMiddleware(t)
	token := issueToken(t, key, kid, "test-issuer", "api", "tenant-1", claims.TAC("rwl"))

	req := httptest.NewRequest(http.MethodGet, "/write-only", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMustHaveTAC_Denied(t *testing.T) {
	router, key, kid := setupMiddleware(t)
	// Token with only 'r' — missing 'w'.
	token := issueToken(t, key, kid, "test-issuer", "api", "tenant-1", claims.TAC("rl"))

	req := httptest.NewRequest(http.MethodGet, "/write-only", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}
