// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber
// Special thanks to Echo: https://github.com/labstack/echo/blob/master/middleware/jwt.go

package jwtware

import (
	"reflect"
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
	cfg := makeCfg(config)

	extractors := cfg.getExtractors()

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
		var token *jwt.Token

		if _, ok := cfg.Claims.(jwt.MapClaims); ok {
			token, err = jwt.Parse(auth, cfg.KeyFunc)
		} else {
			t := reflect.ValueOf(cfg.Claims).Type().Elem()
			claims := reflect.New(t).Interface().(jwt.Claims)
			token, err = jwt.ParseWithClaims(auth, claims, cfg.KeyFunc)
		}
		if err == nil && token.Valid {
			// Store user information from token into context.
			c.Locals(cfg.ContextKey, token)
			return cfg.SuccessHandler(c)
		}
		return cfg.ErrorHandler(c, err)
	}
}
