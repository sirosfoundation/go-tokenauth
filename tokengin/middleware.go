// Package tokengin provides Gin middleware for token validation using go-tokenauth.
package tokengin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	golangjwt "github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"
)

const resultContextKey = "tokenauth_result"

// TokenAuth returns Gin middleware that validates both legacy and new-style tokens.
// It extracts the Bearer token from the Authorization header, validates it,
// and sets the Result into the Gin context.
func TokenAuth(v *validator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token == "" {
			// RFC 6750 §3: the request itself is malformed (no bearer
			// token was even presented), as distinct from a bearer
			// token that was presented but rejected below.
			c.Header("WWW-Authenticate", `Bearer error="invalid_request"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization token",
			})
			return
		}

		result, err := v.Validate(c.Request.Context(), token)
		if err != nil {
			description := invalidTokenDescription(err)
			c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+description+`"`)
			// The existing "error" field/value is kept as-is for
			// backward compatibility with existing consumers (e.g.
			// go-wallet-backend) that may already match on it;
			// error_description is new and additive.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid token",
				"error_description": description,
			})
			return
		}

		c.Set(resultContextKey, result)
		c.Next()
	}
}

// MustHaveTAC returns Gin middleware that requires specific TAC permissions.
// Must be placed after TokenAuth in the middleware chain.
func MustHaveTAC(required string) gin.HandlerFunc {
	return func(c *gin.Context) {
		result, ok := GetResult(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "no authentication context",
			})
			return
		}

		if !result.TAC.HasAll(required) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "insufficient permissions",
			})
			return
		}

		c.Next()
	}
}

// GetResult extracts the validated token result from the Gin context.
func GetResult(c *gin.Context) (*claims.Result, bool) {
	v, exists := c.Get(resultContextKey)
	if !exists {
		return nil, false
	}
	result, ok := v.(*claims.Result)
	return result, ok
}

func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// invalidTokenDescription distinguishes an expired token from every
// other reason validator.Validate rejects a token, for the RFC 6750 §3
// error_description on an invalid_token challenge. There is no separate
// "expired" error code in RFC 6750 — expiry is signaled via
// error_description on invalid_token.
//
// validator.Validate has two live code paths depending on the token's
// alg header, each wrapping a different package's expiry sentinel
// through the returned error chain, so both are checked:
//   - asymmetric tokens (ES256/ES384/EdDSA): go-jose/go-jose's
//     jwt.ErrExpired, from claim validation.
//   - legacy tokens (HS256/HS384/HS512): golang-jwt/jwt/v5's
//     jwt.ErrTokenExpired, a different sentinel from a different
//     package, not the same as the asymmetric path's.
func invalidTokenDescription(err error) string {
	if errors.Is(err, gojosejwt.ErrExpired) || errors.Is(err, golangjwt.ErrTokenExpired) {
		return "the access token expired"
	}
	return "the access token is invalid"
}
