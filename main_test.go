package jwtware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"

	jwtware "github.com/gofiber/jwt/v3"
)

var (
	defaultSigningKey = []byte("secret")

	hamacTokens = []struct {
		SigningMethod string
		Token         string
	}{
		{
			SigningMethod: "HS256",
			Token:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o",
		},
		{
			SigningMethod: "HS384",
			Token:         "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hO2sthNQUSfvI9ylUdMKDxcrm8jB3KL6Rtkd3FOskL-jVqYh2CK1es8FKCQO8_tW",
		},
		{
			SigningMethod: "HS512",
			Token:         "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.wUVS6tazE2N98_J4SH_djkEe1igXPu0qILAvVXCiO6O20gdf5vZ2sYFWX3c-Hy6L4TD47b3DSAAO9XjSqpJfag",
		},
	}
)

func TestJwtFromHeader(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	for _, test := range hamacTokens {
		// Arrange
		app := fiber.New()

		app.Use(jwtware.New(jwtware.Config{
			SigningKey:    defaultSigningKey,
			SigningMethod: test.SigningMethod,
		}))

		app.Get("/ok", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/ok", nil)
		req.Header.Add("Authorization", "Bearer "+test.Token)

		// Act
		resp, err := app.Test(req)

		// Assert
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, 200, resp.StatusCode)
	}
}

func TestJwtFromCookie(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	for _, test := range hamacTokens {
		// Arrange
		app := fiber.New()

		app.Use(jwtware.New(jwtware.Config{
			SigningKey:    defaultSigningKey,
			SigningMethod: test.SigningMethod,
			TokenLookup:   "cookie:Token",
		}))

		app.Get("/ok", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/ok", nil)
		cookie := &http.Cookie{
			Name:  "Token",
			Value: test.Token,
		}
		req.AddCookie(cookie)

		// Act
		resp, err := app.Test(req)

		// Assert
		utils.AssertEqual(t, nil, err)
		utils.AssertEqual(t, 200, resp.StatusCode)
	}
}
