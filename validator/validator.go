// Package validator provides framework-agnostic token validation for both
// new-style asymmetric access tokens and legacy HMAC tokens.
package validator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/jwks"
	"github.com/sirosfoundation/go-tokenauth/revocation"
)

var rfc1123LabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Config configures the token validator.
type Config struct {
	// JWKSURL is the AS's JWKS endpoint (e.g. "https://as.example.com/.well-known/jwks.json").
	// Required for new-style token validation.
	JWKSURL string

	// JWKSRefresh is the background refresh interval for JWKS keys. Default: 5m.
	JWKSRefresh time.Duration

	// TenantID is a static, operator-configured tenant identifier for this
	// Validator's deployment. It is NOT derived from any JWT claim (unlike
	// the per-request routing tenant extracted from an incoming token — see
	// jwks.ContextWithTenantID) and is used only as the X-Tenant-ID fallback
	// for the JWKS fetcher's background refresh, which has no per-call
	// tenant of its own. Optional; leave empty if the JWKS endpoint isn't
	// tenant-aware or this deployment is single-tenant.
	TenantID string

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
		fetcher = jwks.NewFetcher(cfg.JWKSURL, cfg.JWKSRefresh, nil, cfg.TenantID)
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

	if tenantID := issuerRequestTenantID(rawToken); tenantID != "" {
		ctx = jwks.ContextWithTenantID(ctx, tenantID)
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

	// Audience validation is mandatory: an empty configured audience list is
	// a configuration error, not permission to skip the check. go-jose's
	// jwt.Expected treats an empty AnyAudience as "don't check audience at
	// all", which would fail open, so we refuse to validate instead.
	if len(v.cfg.Audiences) == 0 {
		return nil, fmt.Errorf("tokenauth: no audiences configured; refusing to validate without an audience restriction")
	}

	// Validate standard claims.
	expected := jwt.Expected{
		Issuer:      v.cfg.Issuer,
		AnyAudience: v.cfg.Audiences,
		Time:        time.Now(),
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
		Audience: []string(ac.Audience),
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
	// Audience validation is mandatory: an empty configured audience list is
	// a configuration error, not permission to skip the check (omitting
	// gojwt.WithAudience entirely disables audience enforcement, which
	// would fail open).
	if len(v.cfg.Audiences) == 0 {
		return nil, fmt.Errorf("tokenauth: no audiences configured; refusing to validate without an audience restriction")
	}

	// Legacy.Issuers is the source of truth for which issuers legacy tokens
	// may carry. Callers that only set the shared Config.Issuer (used by the
	// asymmetric path) without duplicating it into Legacy.Issuers still get
	// an issuer check here rather than silently having none.
	issuers := v.cfg.Legacy.Issuers
	if len(issuers) == 0 && v.cfg.Issuer != "" {
		issuers = []string{v.cfg.Issuer}
	}
	if len(issuers) == 0 {
		return nil, fmt.Errorf("tokenauth: no legacy issuers configured; refusing to validate without an issuer restriction")
	}

	opts := []gojwt.ParserOption{
		gojwt.WithLeeway(v.cfg.Leeway),
		// A single call with all configured audiences: golang-jwt v5's
		// WithAudience REPLACES the parser's expected-audience set on every
		// call rather than accumulating, so calling it once per audience in
		// a loop silently dropped every audience but the last.
		gojwt.WithAudience(v.cfg.Audiences...),
		// Deliberately NOT using gojwt.WithIssuer here: it only supports a
		// single exact issuer and enforces it inside ParseWithClaims itself,
		// which would hard-reject a token using any accepted issuer other
		// than issuers[0] before the manual multi-issuer check below ever
		// runs. Issuer membership is checked manually after parsing instead,
		// uniformly for one or many configured issuers.
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

	issuerOK := false
	for _, iss := range issuers {
		if lc.Issuer == iss {
			issuerOK = true
			break
		}
	}
	if !issuerOK {
		return nil, fmt.Errorf("tokenauth: legacy token issuer %q not accepted", lc.Issuer)
	}

	return &claims.Result{
		UserID:   lc.UserID,
		DID:      lc.DID,
		TenantID: lc.TenantID,
		JTI:      lc.ID,
		Mode:     claims.ModeLegacy,
		Audience: []string(lc.Audience),
	}, nil
}

type issuerRoutingClaims struct {
	Tenant   string `json:"tenant"`
	TenantID string `json:"tenant_id"`
}

func issuerRequestTenantID(rawToken string) string {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var rc issuerRoutingClaims
	if err := json.Unmarshal(payload, &rc); err != nil {
		return ""
	}

	if rc.Tenant != "" {
		if rfc1123LabelPattern.MatchString(rc.Tenant) {
			return rc.Tenant
		}
		return ""
	}

	if rc.TenantID != "" && rfc1123LabelPattern.MatchString(rc.TenantID) {
		return rc.TenantID
	}

	return ""
}
