package jwtware

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
)

var (
	// ErrJWTMissingOrMalformed is returned when the JWT is missing or malformed.
	ErrJWTMissingOrMalformed = errors.New("missing or malformed JWT")
)

type jwtExtractor func(c *fiber.Ctx) (string, error)

// jwtFromHeader returns a function that extracts token from the request header.
func jwtFromHeader(header string, authScheme string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		auth := c.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && strings.EqualFold(auth[:l], authScheme) {
			return strings.TrimSpace(auth[l:]), nil
		}
		return "", ErrJWTMissingOrMalformed
	}
}

// jwtFromQuery returns a function that extracts token from the query string.
func jwtFromQuery(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Query(param)
		if token == "" {
			return "", ErrJWTMissingOrMalformed
		}
		return token, nil
	}
}

// jwtFromParam returns a function that extracts token from the url param string.
func jwtFromParam(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Params(param)
		if token == "" {
			return "", ErrJWTMissingOrMalformed
		}
		return token, nil
	}
}

// jwtFromCookie returns a function that extracts token from the named cookie.
func jwtFromCookie(name string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Cookies(name)
		if token == "" {
			return "", ErrJWTMissingOrMalformed
		}
		return token, nil
	}
}
