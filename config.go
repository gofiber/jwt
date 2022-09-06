package jwtware

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

// KeyRefreshSuccessHandler is a function signature that consumes a set of signing key set.
// Presence of original signing key set allows to update configuration or stop background refresh.
type KeyRefreshSuccessHandler func(j *KeySet)

// KeyRefreshErrorHandler is a function signature that consumes a set of signing key set and an error.
// Presence of original signing key set allows to update configuration or stop background refresh.
type KeyRefreshErrorHandler func(j *KeySet, err error)

// Config defines the config for JWT middleware
type Config struct {
	// Filter defines a function to skip middleware.
	// Optional. Default: nil
	Filter func(*fiber.Ctx) bool

	// SuccessHandler defines a function which is executed for a valid token.
	// Optional. Default: nil
	SuccessHandler fiber.Handler

	// ErrorHandler defines a function which is executed for an invalid token.
	// It may be used to define a custom JWT error.
	// Optional. Default: 401 Invalid or expired JWT
	ErrorHandler fiber.ErrorHandler

	// Signing key to validate token. Used as fallback if SigningKeys has length 0.
	// Required. This, SigningKeys or KeySetUrl.
	SigningKey interface{}

	// Map of signing keys to validate token with kid field usage.
	// Required. This, SigningKey or KeySetUrl(deprecated) or KeySetUrls.
	SigningKeys map[string]interface{}

	// URL where set of private keys could be downloaded.
	// Required. This, SigningKey or SigningKeys or KeySetURLs
	// Deprecated, use KeySetURLs
	KeySetURL string

	// URLs where set of private keys could be downloaded.
	// Required. This, SigningKey or SigningKeys or KeySetURL(deprecated)
	// duplicate key entries are overwritten as encountered across urls
	KeySetURLs []string

	// KeyRefreshSuccessHandler defines a function which is executed on successful refresh of key set.
	// Optional. Default: nil
	KeyRefreshSuccessHandler KeyRefreshSuccessHandler

	// KeyRefreshErrorHandler defines a function which is executed for refresh key set failure.
	// Optional. Default: nil
	KeyRefreshErrorHandler KeyRefreshErrorHandler

	// KeyRefreshInterval is the duration to refresh the JWKs in the background via a new HTTP request. If this is not nil,
	// then a background refresh will be requested in a separate goroutine at this interval until the JWKs method
	// EndBackground is called.
	// Optional. If set, the value will be used only if `KeySetUrl`(deprecated) or `KeySetUrls` is also present
	KeyRefreshInterval *time.Duration

	// KeyRefreshRateLimit limits the rate at which refresh requests are granted. Only one refresh request can be queued
	// at a time any refresh requests received while there is already a queue are ignored. It does not make sense to
	// have RefreshInterval's value shorter than this.
	// Optional. If set, the value will be used only if `KeySetUrl`(deprecated) or `KeySetUrls` is also present
	KeyRefreshRateLimit *time.Duration

	// KeyRefreshTimeout is the duration for the context used to create the HTTP request for a refresh of the JWKs. This
	// defaults to one minute. This is only effectual if RefreshInterval is not nil.
	// Optional. If set, the value will be used only if `KeySetUrl`(deprecated) or `KeySetUrls` is also present
	KeyRefreshTimeout *time.Duration

	// KeyRefreshUnknownKID indicates that the JWKs refresh request will occur every time a kid that isn't cached is seen.
	// Without specifying a RefreshInterval a malicious client could self-sign X JWTs, send them to this service,
	// then cause potentially high network usage proportional to X.
	// Optional. If set, the value will be used only if `KeySetUrl`(deprecated) or `KeySetUrls` is also present
	KeyRefreshUnknownKID *bool

	// Signing method, used to check token signing method.
	// Optional. Default: "HS256".
	// Possible values: "HS256", "HS384", "HS512", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512"
	SigningMethod string

	// Context key to store user information from the token into context.
	// Optional. Default: "user".
	ContextKey string

	// Claims are extendable claims data defining token content.
	// Optional. Default value jwt.MapClaims
	Claims jwt.Claims

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "param:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// AuthScheme to be used in the Authorization header.
	// Optional. Default: "Bearer".
	AuthScheme string

	// KeyFunc defines a user-defined function that supplies the public key for a token validation.
	// The function shall take care of verifying the signing algorithm and selecting the proper key.
	// A user-defined KeyFunc can be useful if tokens are issued by an external party.
	//
	// When a user-defined KeyFunc is provided, SigningKey, SigningKeys, and SigningMethod are ignored.
	// This is one of the three options to provide a token validation key.
	// The order of precedence is a user-defined KeyFunc, SigningKeys and SigningKey.
	// Required if neither SigningKeys nor SigningKey is provided.
	// Default to an internal implementation verifying the signing algorithm and selecting the proper key.
	KeyFunc jwt.Keyfunc
}

// makeCfg function will check correctness of supplied configuration
// and will complement it with default values instead of missing ones
func makeCfg(config []Config) (cfg Config) {
	if len(config) > 0 {
		cfg = config[0]
	}
	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = func(c *fiber.Ctx) error {
			return c.Next()
		}
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *fiber.Ctx, err error) error {
			if err.Error() == "Missing or malformed JWT" {
				return c.Status(fiber.StatusBadRequest).SendString("Missing or malformed JWT")
			}
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid or expired JWT")
		}
	}
	if cfg.KeySetURL != "" {
		cfg.KeySetURLs = append(cfg.KeySetURLs, cfg.KeySetURL)
	}
	if cfg.SigningKey == nil && len(cfg.SigningKeys) == 0 && len(cfg.KeySetURLs) == 0 && cfg.KeyFunc == nil {
		panic("Fiber: JWT middleware requires signing key or url where to download one")
	}
	if cfg.SigningMethod == "" && len(cfg.KeySetURLs) == 0 {
		cfg.SigningMethod = "HS256"
	}
	if cfg.ContextKey == "" {
		cfg.ContextKey = "user"
	}
	if cfg.Claims == nil {
		cfg.Claims = jwt.MapClaims{}
	}
	if cfg.TokenLookup == "" {
		cfg.TokenLookup = defaultTokenLookup
	}
	if cfg.AuthScheme == "" {
		cfg.AuthScheme = "Bearer"
	}
	if cfg.KeyRefreshTimeout == nil {
		cfg.KeyRefreshTimeout = &defaultKeyRefreshTimeout
	}

	if cfg.KeyFunc == nil {
		if len(cfg.KeySetURLs) > 0 {
			jwks := &KeySet{
				Config: &cfg,
			}
			cfg.KeyFunc = jwks.keyFunc()
		} else {
			cfg.KeyFunc = jwtKeyFunc(cfg)
		}
	}
	return cfg
}

// getExtractors function will create a slice of functions which will be used
// for token sarch  and will perform extraction of the value
func (cfg *Config) getExtractors() []jwtExtractor {
	// Initialize
	extractors := make([]jwtExtractor, 0)
	rootParts := strings.Split(cfg.TokenLookup, ",")
	for _, rootPart := range rootParts {
		parts := strings.Split(strings.TrimSpace(rootPart), ":")

		switch parts[0] {
		case "header":
			extractors = append(extractors, jwtFromHeader(parts[1], cfg.AuthScheme))
		case "query":
			extractors = append(extractors, jwtFromQuery(parts[1]))
		case "param":
			extractors = append(extractors, jwtFromParam(parts[1]))
		case "cookie":
			extractors = append(extractors, jwtFromCookie(parts[1]))
		}
	}
	return extractors
}
