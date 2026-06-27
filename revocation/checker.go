// Package revocation defines the interface for token revocation checking.
package revocation

import "context"

// Checker determines whether a token has been revoked.
type Checker interface {
	// IsRevoked returns true if the token identified by jti has been revoked.
	IsRevoked(ctx context.Context, jti string) bool
}
