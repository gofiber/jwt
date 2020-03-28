### JSON Web Tokens
JWT returns a JSON Web Token (JWT) auth middleware.
For valid token, it sets the user in Ctx.Locals and calls next handler.
For invalid token, it returns "401 - Unauthorized" error.
For missing token, it returns "400 - Bad Request" error.

### Install
```
go get -u github.com/gofiber/fiber
go get -u github.com/gofiber/jwt
```

### Signature
```go
jwt.New(config ...jwt.Config) func(*fiber.Ctx)
```

### Config
| Property | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| Filter | `func(*Ctx) bool` | Defines a function to skip middleware | `nil` |
| SuccessHandler | `func(*fiber.Ctx)` |  SuccessHandler defines a function which is executed for a valid token. | `nil` |
| ErrorHandler | `func(*fiber.Ctx, error)` | ErrorHandler defines a function which is executed for an invalid token. | `401 Invalid or expired JWT` |
| SigningKey | `interface{}` | Signing key to validate token. Used as fallback if SigningKeys has length 0. | `nil` |
| SigningKeys | `map[string]interface{}` | Map of signing keys to validate token with kid field usage. | `nil` |
| SigningMethod | `string` | Signing method, used to check token signing method. Possible values: `HS256`, `HS384`, `HS512`, `ES256`, `ES384`, `ES512` | `"HS256"` |
| ContextKey | `string` | Context key to store user information from the token into context. | `"user"` |
| Claims | `jwt.Claim` | Claims are extendable claims data defining token content. | `jwt.MapClaims{}` |
| TokenLookup | `string` | TokenLookup is a string in the form of "<source>:<name>" that is used | `"header:Authorization"` |
| AuthScheme | `string` |AuthScheme to be used in the Authorization header. | `"Bearer"` |


### Example
```go
package main

import (
  "github.com/gofiber/fiber"
  "github.com/gofiber/jwt"
)

func main() {
  app := fiber.New()

  app.Use(jwt.New(jwt.Config{
    SigningKey: []byte("secret"),
    TokenLookup: "query:token",
  }))

  app.Get("/", func(c *fiber.Ctx) {
    c.Send("Welcome!")
  })

  app.Listen(3000)
}
```