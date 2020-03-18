### JWT Authentication
JWT auth middleware provides an HTTP authentication with `Authorization` header. It calls the next handler for valid `Bearer` token and `401 Unauthorized` for missing or invalid credentials.

### Install
```
go get -u github.com/gofiber/fiber
go get -u github.com/raymayemir/jwt
```

### Signature
```go
jwt.New(config ...jwt.Config) func(*fiber.Ctx)
```

### Config
| Property | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| NonAuth | `[]string` | List of endpoints that doesn't require auth | `[]string` |
| TokenPassword | `string` | Key to check sign | `string` |
| Model | `struct { User string jwt.StandardClaims }` | Describe in what form we want to write to the jwt body | `jwt.StandardClaims` |
| ErrorMessage | `map[string]interface{}` | Error message we want to return in the absence of a token | `map[string]interface{}` |
| Unauthorized | `func(*fiber.Ctx)` | Custom response body for unauthorized responses | `nil` |


### Example
```go
package main

import (
    "github.com/gofiber/fiber"
    "github.com/raymayemir/jwt"
)

func main() {
    app := fiber.New()
    
    cfg := jwt.Config{
    	NotAuth:       []string{"/"},
    	TokenPassword: "secret",
    }
    app.Use(jwt.New(cfg))
    
    app.Get("/", func(c *fiber.Ctx) {
        c.Send("Hello Guest!")
    })
    
    app.Get("/auth", func(c *fiber.Ctx) {
        c.Send("Hello User!")
    })

    app.Listen(3000)
}
```

### Test
```curl
curl --location --request GET 'http://localhost:3000/auth' \
--header 'Authorization: Bearer SomeRandomString'
```

### Additional
Fiber JWT middleware [example project](https://github.com/raymayemir/fiber-jwt-example) 