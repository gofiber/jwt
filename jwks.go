package jwtware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (

	// ErrKIDNotFound indicates that the given key ID was not found in the JWKs.
	ErrKIDNotFound = errors.New("the given key ID was not found in the JWKs")

	// ErrMissingAssets indicates there are required assets missing to create a public key.
	ErrMissingAssets = errors.New("required assets are missing to create a public key")
)

// ErrorHandler is a function signature that consumes an error.
type ErrorHandler func(err error)

// rawJWK represents a raw key inside a JWKs.
type rawJWK struct {
	Curve       string `json:"crv"`
	Exponent    string `json:"e"`
	ID          string `json:"kid"`
	Modulus     string `json:"n"`
	X           string `json:"x"`
	Y           string `json:"y"`
	precomputed interface{}
}

// rawJWKs represents a JWKs in JSON format.
type rawJWKs struct {
	Keys []rawJWK `json:"keys"`
}

// keySet represents a JSON Web Key Set.
type keySet struct {
	keys   map[string]*rawJWK
	config *Config

	cancel              context.CancelFunc
	client              *http.Client
	ctx                 context.Context
	mux                 sync.RWMutex
	refreshErrorHandler ErrorHandler
	refreshInterval     *time.Duration
	refreshRateLimit    *time.Duration
	refreshRequests     chan context.CancelFunc
	refreshUnknownKID   bool
}

// New creates a new JWKs from a raw JSON message.
func parseKeySet(jwksBytes json.RawMessage) (jwks *keySet, err error) {

	// Turn the raw JWKs into the correct Go type.
	var rawKS rawJWKs
	if err = json.Unmarshal(jwksBytes, &rawKS); err != nil {
		return nil, err
	}

	// Iterate through the keys in the raw JWKs. Add them to the JWKs.
	jwks = &keySet{
		keys: make(map[string]*rawJWK, len(rawKS.Keys)),
	}
	for _, key := range rawKS.Keys {
		key := key
		jwks.keys[key.ID] = &key
	}

	return jwks, nil
}

// EndBackground ends the background goroutine to update the JWKs. It can only happen once and is only effective if the
// JWKs has a background goroutine refreshing the JWKs keys.
func (j *keySet) EndBackground() {
	if j.cancel != nil {
		j.cancel()
	}
}

// getKey gets the JSONKey from the given KID from the JWKs. It may refresh the JWKs if configured to.
func (j *keySet) getKey(kid string) (jsonKey *rawJWK, err error) {

	// Get the JSONKey from the JWKs.
	var ok bool
	j.mux.RLock()
	jsonKey, ok = j.keys[kid]
	j.mux.RUnlock()

	// Check if the key was present.
	if !ok {

		// Check to see if configured to refresh on unknown kid.
		if j.refreshUnknownKID {

			// Create a context for refreshing the JWKs.
			ctx, cancel := context.WithCancel(j.ctx)

			// Refresh the JWKs.
			select {
			case <-j.ctx.Done():
				return
			case j.refreshRequests <- cancel:
			default:

				// If the j.refreshRequests channel is full, return the error early.
				return nil, ErrKIDNotFound
			}

			// Wait for the JWKs refresh to done.
			<-ctx.Done()

			// Lock the JWKs for async safe use.
			j.mux.RLock()
			defer j.mux.RUnlock()

			// Check if the JWKs refresh contained the requested key.
			if jsonKey, ok = j.keys[kid]; ok {
				return jsonKey, nil
			}
		}

		return nil, ErrKIDNotFound
	}

	return jsonKey, nil
}