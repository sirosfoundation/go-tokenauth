# go-tokenauth

<div align="center">

[![CI](https://github.com/sirosfoundation/go-tokenauth/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-tokenauth/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-tokenauth.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-tokenauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-tokenauth)](https://goreportcard.com/report/github.com/sirosfoundation/go-tokenauth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/go-tokenauth)](go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/go-tokenauth/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/go-tokenauth)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](LICENSE)

</div>

Shared token validation library for SIROS AS-issued access tokens. Provides a single Go module that any service in the SIROS ecosystem can import to validate tokens, replacing per-service middleware duplication.

## Packages

| Package | Import | Description |
|---------|--------|-------------|
| `claims` | `github.com/sirosfoundation/go-tokenauth/claims` | TAC type, AccessTokenClaims, Result, AuthMode |
| `jwks` | `github.com/sirosfoundation/go-tokenauth/jwks` | JWKS fetcher with background refresh and key rotation |
| `validator` | `github.com/sirosfoundation/go-tokenauth/validator` | Dual-mode validator (asymmetric + legacy HMAC) |
| `revocation` | `github.com/sirosfoundation/go-tokenauth/revocation` | Revocation checker interface |
| `tokengin` | `github.com/sirosfoundation/go-tokenauth/tokengin` | Gin middleware (TokenAuth, MustHaveTAC) |

## Usage

```go
import (
    "github.com/sirosfoundation/go-tokenauth/validator"
    "github.com/sirosfoundation/go-tokenauth/tokengin"
)

// Create validator
v := validator.New(validator.Config{
    JWKSURL:   "https://as.example.com/.well-known/jwks.json",
    Issuer:    "https://as.example.com",
    Audiences: []string{"my-service"},
    Legacy: validator.LegacyConfig{
        Enabled:    true,
        HMACSecret: []byte(os.Getenv("HMAC_SECRET")),
        Issuers:    []string{"https://as.example.com"},
    },
})
v.Start(ctx)
defer v.Stop()

// Use as Gin middleware
router.Use(tokengin.TokenAuth(v))

// Require specific permissions
router.GET("/admin", tokengin.MustHaveTAC("a"), adminHandler)

// Access validated result in handlers
func handler(c *gin.Context) {
    result, _ := tokengin.GetResult(c)
    fmt.Println(result.UserID, result.TenantID, result.TAC)
}
```

## Development

```bash
make test       # Run tests
make lint       # Run linter
make coverage   # Generate coverage report
```

## License

BSD 2-Clause — see [LICENSE](LICENSE).
