// Package claims defines the token claim types used by the SIROS Authorization Server.
// These types are shared between the AS (issuer) and service consumers (validators).
package claims

import (
	"fmt"

	"github.com/go-jose/go-jose/v4/jwt"
)

// TAC represents token access control permissions as a string of permission characters.
type TAC string

const (
	TACRead     byte = 'r' // read access on a per-object basis
	TACWrite    byte = 'w' // write access on a per-object basis
	TACList     byte = 'l' // read access on collections/indexes
	TACInsert   byte = 'i' // create new entries
	TACDelete   byte = 'd' // remove objects
	TACDelegate byte = 'k' // issue delegation tokens
	TACAdmin    byte = 'a' // full administrative rights
)

// validTACChars is the set of valid TAC permission characters.
var validTACChars = map[byte]bool{
	TACRead: true, TACWrite: true, TACList: true,
	TACInsert: true, TACDelete: true, TACDelegate: true,
	TACAdmin: true,
}

// Has returns true if the TAC contains the given permission character.
func (t TAC) Has(perm byte) bool {
	for i := range t {
		if t[i] == perm {
			return true
		}
	}
	return false
}

// HasAll returns true if the TAC contains all characters in perms.
func (t TAC) HasAll(perms string) bool {
	for i := range perms {
		if !t.Has(perms[i]) {
			return false
		}
	}
	return true
}

// IsSubsetOf returns true if every permission in t is also in other.
func (t TAC) IsSubsetOf(other TAC) bool {
	for i := range t {
		if !other.Has(t[i]) {
			return false
		}
	}
	return true
}

// Validate returns an error if the TAC contains invalid characters.
func (t TAC) Validate() error {
	for i := range t {
		if !validTACChars[t[i]] {
			return fmt.Errorf("invalid tac character %q at position %d", t[i], i)
		}
	}
	return nil
}

// AccessTokenClaims represents the claims in an AS-issued access token (asymmetric, new-style).
type AccessTokenClaims struct {
	jwt.Claims

	// TenantID is the tenant scope. "*" means cross-tenant.
	TenantID string `json:"tenant_id"`

	// TAC is the token access control permission set.
	TAC TAC `json:"tac"`

	// ACR is the authentication context class reference.
	ACR string `json:"acr,omitempty"`
}

// AuthMode indicates whether the token was legacy (HMAC) or new-style (asymmetric).
type AuthMode string

const (
	// ModeLegacy indicates a legacy HMAC-signed all-in-one token.
	ModeLegacy AuthMode = "legacy"
	// ModeSession indicates a new-style asymmetric access token.
	ModeSession AuthMode = "session"
)

// Result is the validated identity context extracted from a token.
// Services use this regardless of whether the original token was legacy or new-style.
type Result struct {
	UserID   string
	DID      string
	TenantID string
	TAC      TAC
	ACR      string
	JTI      string
	Mode     AuthMode
}
