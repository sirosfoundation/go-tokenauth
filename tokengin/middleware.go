// Package tokengin provides Gin middleware for token validation using go-tokenauth.
package tokengin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization token",
			})
			return
		}

		result, err := v.Validate(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
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
