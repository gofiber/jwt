package jwtware_test

import (
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"

	jwtware "github.com/gofiber/jwt/v3"
)

type TestToken struct {
	SigningMethod string
	Token         string
}

var (
	hamac = []TestToken{
		{
			SigningMethod: jwtware.HS256,
			Token:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o",
		},
		{
			SigningMethod: jwtware.HS384,
			Token:         "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.hO2sthNQUSfvI9ylUdMKDxcrm8jB3KL6Rtkd3FOskL-jVqYh2CK1es8FKCQO8_tW",
		},
		{
			SigningMethod: jwtware.HS512,
			Token:         "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.wUVS6tazE2N98_J4SH_djkEe1igXPu0qILAvVXCiO6O20gdf5vZ2sYFWX3c-Hy6L4TD47b3DSAAO9XjSqpJfag",
		},
	}

	rsa = []TestToken{
		{
			SigningMethod: jwtware.RS256,
			Token:         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcnNhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.gvWLzl1sYUXdYqAPqFYLEJYtqPce8YxrV6LPiyWX2147llj1YfquFySnC8KOUTykCAxZHe6tFkyyZOp35HOqV3P-jxW2rw05mpNhld79f-O2sAFEzV7qxJXuYi4TL-Qn1gaLWP7i9B6B9c-0xLzYUmtLdrmlM2pxfPkXwG0oSao",
		},
		{
			SigningMethod: jwtware.RS384,
			Token:         "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcnNhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.IIFu5jNRT5fIe91we3ARLTpE8hGu4tK6gsWtrJ1lAWzCxUYsVE02yOi3ya9RJsh-37GN8LdfVw74ZQzr4dwuq8SorycVatA2bc_OfkWpioOoPCqGMBFgsEdue0qtL1taflA-YSNG-Qntpqx_ciCGfI1DhiqikLaL-LSe8H9YOWk",
		},
		{
			SigningMethod: jwtware.RS512,
			Token:         "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcnNhIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.DKY-VXa6JJUZpupEUcmXETwaV2jfLydyeBfhSP8pIEW9g52fQ3g5hrHCNstxG2yy9yU68yrFqrBDetDX_yJ6qSHAOInwGWYot8W4D0lJvqsHJe0W0IPi03xiaWjwKO26xENCUzNNLvSPKPox5DPcg31gzCFBrIUgVX-TkpajuSE",
		},
	}

	ecdsa = []TestToken{
		{
			SigningMethod: jwtware.ES256,
			Token:         "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcC0yNTYifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.n6iJptkq2i6Y6gbuc92f2ExT9oXbg7hdMlR5MvkCZjayxBAyfpIGGoQAjMriwEs4rjF5F-DSU8T6eUcDxNhonA",
		},
		{
			SigningMethod: jwtware.ES384,
			Token:         "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcC0zODQifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.WYGFC6NTSzD1E3Zv7Lyy3m_1l0zoF2tZqvDBxQBXqJN-bStTBzNYnpWZDMN6XMI7OqFbPGlh_Jff4Z4dlf0bieEfenURdtpoLIQI1zPNXoIfaY7TH8BTAXQKtoBk89Ed",
		},
		{
			SigningMethod: jwtware.ES512,
			Token:         "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6ImdvZmliZXItcC01MjEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ADwlteggILiCM_oCkxsyJTRK6BpQyH2FBQD_Tw_ph0vpLPRrpAkyh_CZIY9uZqqpb3J_eohscCzj5Vo9jrhP9DFRAdvLZCgehLj6N8P9aro2uy9jAl7kowxe0nEErv1SrD9qlyLWJh80jJVHRBVHXXysQ2WUD0KiRBq4x1p8jdEw5vHy",
		},
	}
)

const (
	defaultSigningKey = "secret"
	defaultKeySet     = `
{
   "keys":[
	   {
			"e": "AQAB",
			"kid": "gofiber-rsa",
			"kty": "RSA",
			"n": "2IPZysef6KVySrb_RPopuwWy1C7KRfE96zQ9jIRwPghlvs0yfj9VK4rqeYbuHp5k9ghbjm1Bn2LMLR-JzqYWbchxzVrV58ay4nRHYUSjyzdbNcG0J4W-NxHnVqK0UUOl59uikRDqGHh3eRen_jVO_B8lvhqM57HQhA-czHbsmeU"
		},
		{
			"crv": "P-256",
			"kid": "gofiber-p-256",
			"kty": "EC",
			"x": "nLZJMz-8B6p2A1-owmTrCZqZx87_Y5soNPW74dQ8EDw",
			"y": "RvuLyi0tS-Tcx35IMy6aL_ID0K-cJFXmkFR8t9XJ4pc"
		},
		{
			"crv": "P-384",
			"kid": "gofiber-p-384",
			"kty": "EC",
			"x": "wvSt-v7az1qbz493ToTSvNcXgdIGqTtlcLzW7B1Ko3QWVgmtBYWQr_Q311_QX9DY",
			"y": "DvvBgCVjsDyttGAF8cmTP5maV46PrxACZFLvC1OEiZh-Ul0obSGXqG2xu8ulINPy"
		},
		{
			"crv": "P-521",
			"kid": "gofiber-p-521",
			"kty": "EC",
			"x": "AZhzdsnk9Dx5fLdPDnYJOI3ClkghbyFvpSq2ExzyPNgjZz_7iBUjyyLtr6QDn9BAaeFvSQFHvhZUylIQZ9wdIinq",
			"y": "AC2Me0tRqydVv7d23_0xdjiDndGuk0XpSZL5jeDWQ1_Tuty28-pJrFx38QQmWnosC0lBEdOUjxq-71YP7e4TzRMR"
		}
	]
}
`
)

func TestJwtFromHeader(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	for _, test := range hamac {
		// Arrange
		app := fiber.New()

		app.Use(jwtware.New(jwtware.Config{
			SigningKey:    []byte(defaultSigningKey),
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

	for _, test := range hamac {
		// Arrange
		app := fiber.New()

		app.Use(jwtware.New(jwtware.Config{
			SigningKey:    []byte(defaultSigningKey),
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

// TestJWKs performs a table test on the JWKs code.
func TestJwkFromServer(t *testing.T) {
	// Could add a test with an invalid JWKs endpoint.
	// Create a temporary directory to serve the JWKs from.
	tempDir, err := ioutil.TempDir("", "*")
	if err != nil {
		t.Errorf("Failed to create a temporary directory.\nError:%s\n", err.Error())
		t.FailNow()
	}
	defer func() {
		if err = os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temporary directory.\nError:%s\n", err.Error())
			t.FailNow()
		}
	}()

	// Create the JWKs file path.
	jwksFile := filepath.Join(tempDir, "jwks.json")

	// Write the empty JWKs.
	if err = ioutil.WriteFile(jwksFile, []byte(defaultKeySet), 0600); err != nil {
		t.Errorf("Failed to write JWKs file to temporary directory.\nError:%s\n", err.Error())
		t.FailNow()
	}

	// Create the HTTP test server.
	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	// Iterate through the test cases.
	for _, test := range append(rsa, ecdsa...) {
		// Arrange
		app := fiber.New()

		app.Use(jwtware.New(jwtware.Config{
			KeySetURL: server.URL + "/jwks.json",
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

func TestCustomKeyFunc(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	test := hamac[0]
	// Arrange
	app := fiber.New()

	app.Use(jwtware.New(jwtware.Config{
		KeyFunc: customKeyFunc(),
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

func customKeyFunc() jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		// Always check the signing method
		if t.Method.Alg() != jwtware.HS256 {
			return nil, fmt.Errorf("Unexpected jwt signing method=%v", t.Header["alg"])
		}

		return []byte(defaultSigningKey), nil
	}
}
