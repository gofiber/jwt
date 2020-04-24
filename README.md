### JSON Web Tokens
JWT returns a JSON Web Token (JWT) auth middleware.
For valid token, it sets the user in Ctx.Locals and calls next handler.
For invalid token, it returns "401 - Unauthorized" error.
For missing token, it returns "400 - Bad Request" error.

Special thanks and credits to [Echo](https://echo.labstack.com/middleware/jwt)

### Install
```
go get -u github.com/gofiber/fiber
go get -u github.com/gofiber/jwt
go get -u github.com/dgrijalva/jwt-go
```

### Signature
```go
jwtware.New(config ...jwtware.Config) func(*fiber.Ctx)
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
| TokenLookup | `string` | TokenLookup is a string in the form of `<source>:<name>` that is used | `"header:Authorization"` |
| AuthScheme | `string` |AuthScheme to be used in the Authorization header. | `"Bearer"` |


### Example
```go
package main

import (
  "github.com/dgrijalva/jwt-go"

  "github.com/gofiber/fiber"
  "github.com/gofiber/jwt" // jwtware
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

  app.Listen(3000)
}

func login(c *fiber.Ctx) {
  user := c.FormValue("user")
  pass := c.FormValue("pass")

  // Throws Unauthorized error
  if user != "john" || pass != "doe" {
    c.SendStatus(fiber.StatusUnauthorized)
    return
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
    c.SendStatus(fiber.StatusInternalServerError)
    return
  }

  c.JSON(fiber.Map{"token": t})
}

func accessible(c *fiber.Ctx) {
  c.Send("Accessible")
}

func restricted(c *fiber.Ctx) {
  user := c.Locals("user").(*jwt.Token)
  claims := user.Claims.(jwt.MapClaims)
  name := claims["name"].(string)
  c.Send("Welcome " + name)
}
```

### Test
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
