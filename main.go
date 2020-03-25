// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber"
	"strings"
)

type Config struct {
	// Filter defines a function to skip middleware.
	// Optional. Default: nil
	Filter func(*fiber.Ctx) bool
	// List of endpoints that doesn't require auth.
	// Optional. Default: []string
	NotAuth []string
	// Password needs to check sign
	// Required. Default: ""
	TokenPassword string
	// Unauthorized defines the response body for unauthorized responses.
	// Optional. Default: nil
	Unauthorized func(*fiber.Ctx)
	// The model is needed to describe
	// in what form we want to write to the jwt body
	// Required. Default: struct with jwt.StandardClaims
	Model struct {
		User string
		jwt.StandardClaims
	}
	// Error message we want to return in the absence of a token
	// Optional.
	ErrorMessage map[string]interface{}
}

func New(config ...Config) func(*fiber.Ctx) {
	// Init config
	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.ErrorMessage == nil {
		cfg.ErrorMessage = map[string]interface{}{
			"status":     false,
			"message":    "Unauthorized",
			"statusCode": 401,
		}
	}

	if cfg.Unauthorized == nil {
		cfg.Unauthorized = func(c *fiber.Ctx) {
			c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			c.SendStatus(401)
			if cfg.ErrorMessage != nil {
				_ = c.JSON(cfg.ErrorMessage)
			}
		}
	}

	// Return middleware handler
	return func(c *fiber.Ctx) {
		// Filter request to skip middleware
		if cfg.Filter != nil && cfg.Filter(c) {
			c.Next()
			return
		}

		requestPath := c.Path() // Current request path

		// Check if request does not need authentication, serve the request if it doesn't need it
		for _, value := range cfg.NotAuth {
			if value == requestPath {
				c.Next()
				return
			}
		}

		tokenHeader := c.Get(fiber.HeaderAuthorization) // Grab the token from the header

		// Check if token is missing
		if len(tokenHeader) > 6 && strings.ToLower(tokenHeader[:6]) == "bearer" {
			// The token normally comes in format `Bearer {token-body}`,
			// we check if the retrieved token matched this requirement
			splitted := strings.Split(tokenHeader, " ")
			if len(splitted) == 2 {
				tokenPart := splitted[1] // Grab the token part, what we are truly interested in
				tk := &cfg.Model

				token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
					return []byte(cfg.TokenPassword), nil
				})

				if err != nil { // Malformed token
					cfg.Unauthorized(c)
					return
				} else {
					if !token.Valid { // Token is invalid, maybe not signed on this server
						cfg.Unauthorized(c)
						return
					}

					c.Next()
					return
				}
			}
		}
		// Authentication failed
		cfg.Unauthorized(c)
	}
}
