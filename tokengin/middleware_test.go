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

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gin-gonic/gin"
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
