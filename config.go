package jwtware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

// Config defines the config for BasicAuth middleware
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
	// Required. This, SigningKey or KeySetUrl.
	SigningKeys map[string]interface{}

	// URL where set of private keys could be downloaded.
	// Required. This, SigningKey or SigningKeys.
	KeySetUrl string

	// KeyRefreshInterval is the duration to refresh the JWKs in the background via a new HTTP request. If this is not nil,
	// then a background refresh will be requested in a separate goroutine at this interval until the JWKs method
	// EndBackground is called.
	// Optional. If set, the value will be used only if `KeySetUrl` is also present
	KeyRefreshInterval *time.Duration

	// KeyRefreshRateLimit limits the rate at which refresh requests are granted. Only one refresh request can be queued
	// at a time any refresh requests received while there is already a queue are ignored. It does not make sense to
	// have RefreshInterval's value shorter than this.
	// Optional. If set, the value will be used only if `KeySetUrl` is also present
	KeyRefreshRateLimit *time.Duration

	// KeyRefreshTimeout is the duration for the context used to create the HTTP request for a refresh of the JWKs. This
	// defaults to one minute. This is only effectual if RefreshInterval is not nil.
	// Optional. If set, the value will be used only if `KeySetUrl` is also present
	KeyRefreshTimeout *time.Duration

	// KeyRefreshUnknownKID indicates that the JWKs refresh request will occur every time a kid that isn't cached is seen.
	// Without specifying a RefreshInterval a malicious client could self-sign X JWTs, send them to this service,
	// then cause potentially high network usage proportional to X.
	// Optional. If set, the value will be used only if `KeySetUrl` is also present
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

	keyFunc jwt.Keyfunc
}
