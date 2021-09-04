// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber
// Special thanks to Echo: https://github.com/labstack/echo/blob/master/middleware/jwt.go

package jwtware

import (
	"reflect"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

var (
	// defaultRefreshTimeout is the default duration for the context used to create the HTTP request for a refresh of
	// the JWKs.
	defaultKeyRefreshTimeout = time.Minute

	defaultTokenLookup = "header:" + fiber.HeaderAuthorization
)

// New ...
func New(config ...Config) fiber.Handler {
	cfg := initCfg(config)

	extractors := initExtractors(cfg)

	// Return middleware handler
	return func(c *fiber.Ctx) error {
		// Filter request to skip middleware
		if cfg.Filter != nil && cfg.Filter(c) {
			return c.Next()
		}
		var auth string
		var err error

		for _, extractor := range extractors {
			auth, err = extractor(c)
			if auth != "" && err == nil {
				break
			}
		}

		if err != nil {
			return cfg.ErrorHandler(c, err)
		}
		token := new(jwt.Token)

		if _, ok := cfg.Claims.(jwt.MapClaims); ok {
			token, err = jwt.Parse(auth, cfg.keyFunc)
		} else {
			t := reflect.ValueOf(cfg.Claims).Type().Elem()
			claims := reflect.New(t).Interface().(jwt.Claims)
			token, err = jwt.ParseWithClaims(auth, claims, cfg.keyFunc)
		}
		if err == nil && token.Valid {
			// Store user information from token into context.
			c.Locals(cfg.ContextKey, token)
			return cfg.SuccessHandler(c)
		}
		return cfg.ErrorHandler(c, err)
	}
}

// initCfg function will check correctness of supplied configuration
// and will complement it with default values instead of missing ones
func initCfg(config []Config) (cfg Config) {
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
	if cfg.SigningKey == nil && len(cfg.SigningKeys) == 0 && cfg.KeySetURL == "" {
		panic("Fiber: JWT middleware requires signing key or url where to download one")
	}
	if cfg.SigningMethod == "" && cfg.KeySetURL == "" {
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
	if cfg.KeySetURL != "" {
		jwks := &KeySet{
			Config: &cfg,
		}
		cfg.keyFunc = jwks.keyFunc()
	} else {
		cfg.keyFunc = jwtKeyFunc(cfg)
	}
	return cfg
}

// initExtractors function will create a slice of functions which will be used
// for token sarch  and will perform extraction of the value
func initExtractors(cfg Config) []jwtExtractor {
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
