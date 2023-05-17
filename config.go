package jwtware

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrJWTAlg is returned when the JWT header did not contain the expected algorithm.
	ErrJWTAlg = errors.New("the JWT header did not contain the expected algorithm")
)

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
	// At least one of the following is required: KeyFunc, JWKSetURLs, SigningKeys, or SigningKey.
	// The order of precedence is: KeyFunc, JWKSetURLs, SigningKeys, SigningKey.
	SigningKey SigningKey

	// Map of signing keys to validate token with kid field usage.
	// At least one of the following is required: KeyFunc, JWKSetURLs, SigningKeys, or SigningKey.
	// The order of precedence is: KeyFunc, JWKSetURLs, SigningKeys, SigningKey.
	SigningKeys map[string]SigningKey

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

	// KeyFunc is a function that supplies the public key for JWT cryptographic verification.
	// The function shall take care of verifying the signing algorithm and selecting the proper key.
	// Internally, github.com/MicahParks/keyfunc/v2 package is used project defaults. If you need more customization,
	// you can provide a jwt.Keyfunc using that package or make your own implementation.
	//
	// At least one of the following is required: KeyFunc, JWKSetURLs, SigningKeys, or SigningKey.
	// The order of precedence is: KeyFunc, JWKSetURLs, SigningKeys, SigningKey.
	KeyFunc jwt.Keyfunc

	// JWKSetURLs is a slice of HTTP URLs that contain the JSON Web Key Set (JWKS) used to verify the signatures of
	// JWTs. Use of HTTPS is recommended. The presence of the "kid" field in the JWT header and JWKs is mandatory for
	// this feature.
	//
	// By default, all JWK Sets in this slice will:
	//   * Refresh every hour.
	//   * Refresh automatically if a new "kid" is seen in a JWT being verified.
	//   * Rate limit refreshes to once every 5 minutes.
	//   * Timeout refreshes after 10 seconds.
	//
	// At least one of the following is required: KeyFunc, JWKSetURLs, SigningKeys, or SigningKey.
	// The order of precedence is: KeyFunc, JWKSetURLs, SigningKeys, SigningKey.
	JWKSetURLs []string
}

// SigningKey holds information about the recognized cryptographic keys used to sign JWTs by this program.
type SigningKey struct {
	// JWTAlg is the algorithm used to sign JWTs. If this value is a non-empty string, this will be checked against the
	// "alg" value in the JWT header.
	//
	// https://www.rfc-editor.org/rfc/rfc7518#section-3.1
	JWTAlg string
	// Key is the cryptographic key used to sign JWTs. For supported types, please see
	// https://github.com/golang-jwt/jwt.
	Key interface{}
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
	if cfg.SigningKey.Key == nil && len(cfg.SigningKeys) == 0 && len(cfg.JWKSetURLs) == 0 && cfg.KeyFunc == nil {
		panic("Fiber: JWT middleware configuration: At least one of the following is required: KeyFunc, JWKSetURLs, SigningKeys, or SigningKey.")
	}
	if cfg.ContextKey == "" {
		cfg.ContextKey = "user"
	}
	if cfg.Claims == nil {
		cfg.Claims = jwt.MapClaims{}
	}
	if cfg.TokenLookup == "" {
		cfg.TokenLookup = defaultTokenLookup
		// set AuthScheme as "Bearer" only if TokenLookup is set to default.
		if cfg.AuthScheme == "" {
			cfg.AuthScheme = "Bearer"
		}
	}

	if cfg.KeyFunc == nil {
		if len(cfg.SigningKeys) > 0 || len(cfg.JWKSetURLs) > 0 {
			var givenKeys map[string]keyfunc.GivenKey
			if cfg.SigningKeys != nil {
				givenKeys = make(map[string]keyfunc.GivenKey, len(cfg.SigningKeys))
				for kid, key := range cfg.SigningKeys {
					givenKeys[kid] = keyfunc.NewGivenCustom(key, keyfunc.GivenKeyOptions{
						Algorithm: key.JWTAlg,
					})
				}
			}
			if len(cfg.JWKSetURLs) > 0 {
				var err error
				cfg.KeyFunc, err = multiKeyfunc(givenKeys, cfg.JWKSetURLs)
				if err != nil {
					panic("Failed to create keyfunc from JWK Set URL: " + err.Error())
				}
			} else {
				cfg.KeyFunc = keyfunc.NewGiven(givenKeys).Keyfunc
			}
		} else {
			cfg.KeyFunc = signingKeyFunc(cfg.SigningKey)
		}
	}

	return cfg
}

func multiKeyfunc(givenKeys map[string]keyfunc.GivenKey, jwkSetURLs []string) (jwt.Keyfunc, error) {
	opts := keyfuncOptions(givenKeys)
	multiple := make(map[string]keyfunc.Options, len(jwkSetURLs))
	for _, url := range jwkSetURLs {
		multiple[url] = opts
	}
	multiOpts := keyfunc.MultipleOptions{
		KeySelector: keyfunc.KeySelectorFirst,
	}
	multi, err := keyfunc.GetMultiple(multiple, multiOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get multiple JWK Set URLs: %w", err)
	}
	return multi.Keyfunc, nil
}

func keyfuncOptions(givenKeys map[string]keyfunc.GivenKey) keyfunc.Options {
	return keyfunc.Options{
		GivenKeys: givenKeys,
		RefreshErrorHandler: func(err error) {
			log.Printf("Failed to perform background refresh of JWK Set: %s.", err)
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}
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

func signingKeyFunc(key SigningKey) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		if key.JWTAlg != "" {
			alg, ok := token.Header["alg"].(string)
			if !ok {
				return nil, fmt.Errorf("unexpected jwt signing method: expected: %q: got: missing or unexpected JSON type", key.JWTAlg)
			}
			if alg != key.JWTAlg {
				return nil, fmt.Errorf("unexpected jwt signing method: expected: %q: got: %q", key.JWTAlg, alg)
			}
		}
		return key.Key, nil
	}
}
