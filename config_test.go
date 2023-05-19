package jwtware

import (
	"testing"
)

func TestPanicOnMissingConfiguration(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err == nil {
			t.Fatalf("Middleware should panic on missing configuration")
		}
	}()

	// Arrange
	config := make([]Config, 0)

	// Act
	makeCfg(config)
}

func TestDefaultConfiguration(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	// Arrange
	config := append(make([]Config, 0), Config{
		SigningKey: SigningKey{Key: []byte("")},
	})

	// Act
	cfg := makeCfg(config)

	// Assert
	if cfg.ContextKey != "user" {
		t.Fatalf("Default context key should be 'user'")
	}
	if cfg.Claims == nil {
		t.Fatalf("Default claims should not be 'nil'")
	}

	if cfg.TokenLookup != defaultTokenLookup {
		t.Fatalf("Default token lookup should be '%v'", defaultTokenLookup)
	}
	if cfg.AuthScheme != "Bearer" {
		t.Fatalf("Default auth scheme should be 'Bearer'")
	}
}

func TestExtractorsInitialization(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	// Arrange
	cfg := Config{
		SigningKey:  SigningKey{Key: []byte("")},
		TokenLookup: defaultTokenLookup + ",query:token,param:token,cookie:token,something:something",
	}

	// Act
	extractors := cfg.getExtractors()

	// Assert
	if len(extractors) != 4 {
		t.Fatalf("Extractors should not be created for invalid lookups")
	}
	if cfg.AuthScheme != "" {
		t.Fatal("AuthScheme should be \"\"")
	}
}

func TestCustomTokenLookup(t *testing.T) {
	t.Parallel()

	defer func() {
		// Assert
		if err := recover(); err != nil {
			t.Fatalf("Middleware should not panic")
		}
	}()

	// Arrange
	lookup := `header:X-Auth`
	scheme := "Token"
	cfg := Config{
		SigningKey:  SigningKey{Key: []byte("")},
		TokenLookup: lookup,
		AuthScheme:  scheme,
	}

	if cfg.TokenLookup != lookup {
		t.Fatalf("TokenLookup should be %s", lookup)
	}
	if cfg.AuthScheme != scheme {
		t.Fatalf("AuthScheme should be %s", scheme)
	}
}
