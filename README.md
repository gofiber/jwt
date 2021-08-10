# JSON Web Tokens

![Release](https://img.shields.io/github/release/gofiber/jwt.svg)
[![Discord](https://img.shields.io/badge/discord-join%20channel-7289DA)](https://gofiber.io/discord)
![Test](https://github.com/gofiber/jwt/workflows/Test/badge.svg)
![Security](https://github.com/gofiber/jwt/workflows/Security/badge.svg)
![Linter](https://github.com/gofiber/jwt/workflows/Linter/badge.svg)

JWT returns a JSON Web Token (JWT) auth middleware.
For valid token, it sets the user in Ctx.Locals and calls next handler.
For invalid token, it returns "401 - Unauthorized" error.
For missing token, it returns "400 - Bad Request" error.

Special thanks and credits to [Echo](https://echo.labstack.com/middleware/jwt)

### Install

This middleware supports Fiber v1 & v2, install accordingly.

```
go get -u github.com/gofiber/fiber/v2
go get -u github.com/gofiber/jwt/v2
go get -u github.com/golang-jwt/jwt/v4
```

### Signature
```go
jwtware.New(config ...jwtware.Config) func(*fiber.Ctx) error
```

### Config
| Property | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| Filter | `func(*fiber.Ctx) bool` | Defines a function to skip middleware | `nil` |
| SuccessHandler | `func(*fiber.Ctx) error` |  SuccessHandler defines a function which is executed for a valid token. | `nil` |
| ErrorHandler | `func(*fiber.Ctx, error) error` | ErrorHandler defines a function which is executed for an invalid token. | `401 Invalid or expired JWT` |
| SigningKey | `interface{}` | Signing key to validate token. Used as fallback if SigningKeys has length 0. | `nil` |
| SigningKeys | `map[string]interface{}` | Map of signing keys to validate token with kid field usage. | `nil` |
| SigningMethod | `string` | Signing method, used to check token signing method. Possible values: `HS256`, `HS384`, `HS512`, `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512` | `"HS256"` |
| ContextKey | `string` | Context key to store user information from the token into context. | `"user"` |
| Claims | `jwt.Claim` | Claims are extendable claims data defining token content. | `jwt.MapClaims{}` |
| TokenLookup | `string` | TokenLookup is a string in the form of `<source>:<name>` that is used | `"header:Authorization"` |
| AuthScheme | `string` |AuthScheme to be used in the Authorization header. | `"Bearer"` |


### HS256 Example
```go
package main

import (
	"time"

	"github.com/gofiber/fiber/v2"

	jwtware "github.com/gofiber/jwt/v2"
	"github.com/golang-jwt/jwt/v4"
)

func main() {
	app := fiber.New()

	// Login route
	app.Post("/login", login)

	// Unauthenticated route
	app.Get("/", accessible)

	// JWT Middleware
	app.Use(jwtware.New(jwtware.Config{
		SigningKey: []byte("secret"),
	}))

	// Restricted Routes
	app.Get("/restricted", restricted)

	app.Listen(":3000")
}

func login(c *fiber.Ctx) error {
	user := c.FormValue("user")
	pass := c.FormValue("pass")

	// Throws Unauthorized error
	if user != "john" || pass != "doe" {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// Create token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = "John Doe"
	claims["admin"] = true
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	return c.JSON(fiber.Map{"token": t})
}

func accessible(c *fiber.Ctx) error {
	return c.SendString("Accessible")
}

func restricted(c *fiber.Ctx) error {
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	return c.SendString("Welcome " + name)
}

```

### HS256 Test
_Login using username and password to retrieve a token._
```
curl --data "user=john&pass=doe" http://localhost:3000/login
```
_Response_
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NjE5NTcxMzZ9.RB3arc4-OyzASAaUhC2W3ReWaXAt_z2Fd3BN4aWTgEY"
}
```


_Request a restricted resource using the token in Authorization request header._
```
curl localhost:3000/restricted -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NjE5NTcxMzZ9.RB3arc4-OyzASAaUhC2W3ReWaXAt_z2Fd3BN4aWTgEY"
```
_Response_
```
Welcome John Doe
```

### RS256 Example
```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"

	jwtware "github.com/gofiber/jwt/v2"
	"github.com/golang-jwt/jwt/v4"
)

var (
	// Obviously, this is just a test example. Do not do this in production.
	// In production, you would have the private key and public key pair generated
	// in advance. NEVER add a private key to any GitHub repo.
	privateKey *rsa.PrivateKey
)

func main() {
	app := fiber.New()

	// Just as a demo, generate a new private/public key pair on each run. See note above.
	rng := rand.Reader
	var err error
	privateKey, err = rsa.GenerateKey(rng, 2048)
	if err != nil {
		log.Fatalf("rsa.GenerateKey: %v", err)
	}

	// Login route
	app.Post("/login", login)

	// Unauthenticated route
	app.Get("/", accessible)

	// JWT Middleware
	app.Use(jwtware.New(jwtware.Config{
		SigningMethod: "RS256",
		SigningKey:    privateKey.Public(),
	}))

	// Restricted Routes
	app.Get("/restricted", restricted)

	app.Listen(":3000")
}

func login(c *fiber.Ctx) error {
	user := c.FormValue("user")
	pass := c.FormValue("pass")

	// Throws Unauthorized error
	if user != "john" || pass != "doe" {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// Create token
	token := jwt.New(jwt.SigningMethodRS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = "John Doe"
	claims["admin"] = true
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	// Generate encoded token and send it as response.
	t, err := token.SignedString(privateKey)
	if err != nil {
		log.Printf("token.SignedString: %v", err)
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	return c.JSON(fiber.Map{"token": t})
}

func accessible(c *fiber.Ctx) error {
	return c.SendString("Accessible")
}

func restricted(c *fiber.Ctx) error {
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	return c.SendString("Welcome " + name)
}

```

### RS256 Test
The RS256 is actually identical to the HS256 test above.
