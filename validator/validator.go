// Package validator provides framework-agnostic token validation for both
// new-style asymmetric access tokens and legacy HMAC tokens.
package validator

import (
	"context"
	"fmt"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/jwks"
	"github.com/sirosfoundation/go-tokenauth/revocation"
)

// Config configures the token validator.
type Config struct {
	// JWKSURL is the AS's JWKS endpoint (e.g. "https://as.example.com/.well-known/jwks.json").
	// Required for new-style token validation.
	JWKSURL string

	// JWKSRefresh is the background refresh interval for JWKS keys. Default: 5m.
	JWKSRefresh time.Duration

	// Issuer is the expected "iss" claim value.
	Issuer string

	// Audiences lists the accepted "aud" values (this service's identifiers).
	Audiences []string

	// Legacy contains configuration for legacy HMAC token validation.
	Legacy LegacyConfig

	// Revocation is an optional revocation checker. If nil, no revocation checking.
	Revocation revocation.Checker

	// Leeway for time-based claim validation. Default: 5s.
	Leeway time.Duration
}

// LegacyConfig configures legacy HMAC token validation during the sunset period.
type LegacyConfig struct {
	// Enabled controls whether legacy tokens are accepted.
	Enabled bool

	// HMACSecret is the shared secret for validating legacy HMAC tokens.
	HMACSecret []byte

	// Issuers lists accepted legacy issuers.
	Issuers []string
}

// Validator validates both new-style and legacy tokens.
type Validator struct {
	cfg     Config
	fetcher *jwks.Fetcher
}

// New creates a Validator. Call Start() to begin background JWKS refresh.
func New(cfg Config) *Validator {
	if cfg.Leeway == 0 {
		cfg.Leeway = 5 * time.Second
	}

	var fetcher *jwks.Fetcher
	if cfg.JWKSURL != "" {
		fetcher = jwks.NewFetcher(cfg.JWKSURL, cfg.JWKSRefresh, nil)
	}

	return &Validator{
		cfg:     cfg,
		fetcher: fetcher,
	}
}

// Start begins background JWKS key refresh. Call Stop() when done.
func (v *Validator) Start(ctx context.Context) {
	if v.fetcher != nil {
		v.fetcher.Start(ctx)
	}
}

// Stop halts background JWKS refresh.
func (v *Validator) Stop() {
	if v.fetcher != nil {
		v.fetcher.Stop()
	}
}

// Validate parses and validates a raw JWT token string.
// It auto-detects the token type from the JWT header algorithm.
func (v *Validator) Validate(ctx context.Context, rawToken string) (*claims.Result, error) {
	// Peek at the JWT header to determine the algorithm without verifying.
	tok, err := gojwt.Parse(rawToken, func(_ *gojwt.Token) (interface{}, error) {
		return nil, fmt.Errorf("inspection only")
	}, gojwt.WithoutClaimsValidation())

	// Even if parsing "fails" (due to our dummy key func), we can inspect the header.
	alg := ""
	if tok != nil {
		if a, ok := tok.Header["alg"].(string); ok {
			alg = a
		}
	}
	if alg == "" && err != nil {
		return nil, fmt.Errorf("tokenauth: failed to parse token header: %w", err)
	}

	switch alg {
	case "HS256", "HS384", "HS512":
		if !v.cfg.Legacy.Enabled {
			return nil, fmt.Errorf("tokenauth: legacy tokens are disabled")
		}
		return v.validateLegacy(rawToken)
	case "ES256", "ES384", "EdDSA":
		return v.validateAsymmetric(ctx, rawToken)
	default:
		return nil, fmt.Errorf("tokenauth: unsupported algorithm %q", alg)
	}
}

// validateAsymmetric validates a new-style ECDSA/EdDSA token.
func (v *Validator) validateAsymmetric(ctx context.Context, rawToken string) (*claims.Result, error) {
	if v.fetcher == nil {
		return nil, fmt.Errorf("tokenauth: JWKS not configured")
	}

	tok, err := jwt.ParseSigned(rawToken, []gojose.SignatureAlgorithm{
		gojose.ES256, gojose.ES384, gojose.EdDSA,
	})
	if err != nil {
		return nil, fmt.Errorf("tokenauth: failed to parse token: %w", err)
	}

	// Get kid from header.
	if len(tok.Headers) == 0 {
		return nil, fmt.Errorf("tokenauth: token has no headers")
	}
	kid := tok.Headers[0].KeyID
	if kid == "" {
		return nil, fmt.Errorf("tokenauth: token missing kid header")
	}

	keys, err := v.fetcher.GetKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("tokenauth: key lookup failed: %w", err)
	}

	// Build a JWKS for verification.
	ks := gojose.JSONWebKeySet{Keys: keys}
	var ac claims.AccessTokenClaims
	if err := tok.Claims(ks, &ac); err != nil {
		return nil, fmt.Errorf("tokenauth: signature verification failed: %w", err)
	}

	// Validate standard claims.
	expected := jwt.Expected{
		Issuer: v.cfg.Issuer,
		Time:   time.Now(),
	}
	if len(v.cfg.Audiences) > 0 {
		expected.AnyAudience = v.cfg.Audiences
	}
	if err := ac.ValidateWithLeeway(expected, v.cfg.Leeway); err != nil {
		return nil, fmt.Errorf("tokenauth: claim validation failed: %w", err)
	}

	// Revocation check.
	if v.cfg.Revocation != nil && ac.ID != "" {
		if v.cfg.Revocation.IsRevoked(ctx, ac.ID) {
			return nil, fmt.Errorf("tokenauth: token revoked")
		}
	}

	return &claims.Result{
		UserID:   ac.Subject,
		TenantID: ac.TenantID,
		TAC:      ac.TAC,
		ACR:      ac.ACR,
		JTI:      ac.ID,
		Mode:     claims.ModeSession,
	}, nil
}

// LegacyTokenClaims are the claims in a legacy all-in-one HMAC token.
type LegacyTokenClaims struct {
	gojwt.RegisteredClaims
	UserID   string `json:"user_id"`
	DID      string `json:"did,omitempty"`
	TenantID string `json:"tenant_id"`
}

// validateLegacy validates a legacy HMAC-signed token.
func (v *Validator) validateLegacy(rawToken string) (*claims.Result, error) {
	opts := []gojwt.ParserOption{
		gojwt.WithLeeway(v.cfg.Leeway),
	}
	// Add issuer validation if configured.
	if len(v.cfg.Legacy.Issuers) > 0 {
		// golang-jwt only supports single issuer — check first, validate rest manually.
		opts = append(opts, gojwt.WithIssuer(v.cfg.Legacy.Issuers[0]))
	}
	for _, aud := range v.cfg.Audiences {
		opts = append(opts, gojwt.WithAudience(aud))
	}

	token, err := gojwt.ParseWithClaims(rawToken, &LegacyTokenClaims{}, func(t *gojwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("tokenauth: unexpected signing method: %v", t.Header["alg"])
		}
		return v.cfg.Legacy.HMACSecret, nil
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("tokenauth: legacy token validation failed: %w", err)
	}

	lc, ok := token.Claims.(*LegacyTokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("tokenauth: invalid legacy token claims")
	}

	// Check additional issuers if more than one configured.
	if len(v.cfg.Legacy.Issuers) > 1 {
		issuerOK := false
		for _, iss := range v.cfg.Legacy.Issuers {
			if lc.Issuer == iss {
				issuerOK = true
				break
			}
		}
		if !issuerOK {
			return nil, fmt.Errorf("tokenauth: legacy token issuer %q not accepted", lc.Issuer)
		}
	}

	return &claims.Result{
		UserID:   lc.UserID,
		DID:      lc.DID,
		TenantID: lc.TenantID,
		JTI:      lc.ID,
		Mode:     claims.ModeLegacy,
	}, nil
}
