package jwtware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var ( // ErrKID indicates that the JWT had an invalid kid.
	errMissingKeySet = errors.New("not able to download JWKs")

	// errKID indicates that the JWT had an invalid kid.
	errKID = errors.New("the JWT has an invalid kid")

	// errUnsupportedKeyType indicates the JWT key type is an unsupported type.
	errUnsupportedKeyType = errors.New("the JWT key type is unsupported")

	// errKIDNotFound indicates that the given key ID was not found in the JWKs.
	errKIDNotFound = errors.New("the given key ID was not found in the JWKs")

	// errMissingAssets indicates there are required assets missing to create a public key.
	errMissingAssets = errors.New("required assets are missing to create a public key")
)

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

// KeySet represents a JSON Web Key Set.
type KeySet struct {
	Keys            map[string]*rawJWK
	Config          *Config
	cancel          context.CancelFunc
	client          *http.Client
	ctx             context.Context
	mux             sync.RWMutex
	refreshRequests chan context.CancelFunc
}

// keyFunc is a compatibility function that matches the signature of github.com/dgrijalva/jwt-go's keyFunc function.
func (j *KeySet) keyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		if j.Keys == nil {
			err := j.downloadKeySet()
			if err != nil {
				return nil, fmt.Errorf("%w: key set URL is not accessible", errMissingKeySet)
			}
		}

		// Get the kid from the token header.
		kidInter, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("%w: could not find kid in JWT header", errKID)
		}
		kid, ok := kidInter.(string)
		if !ok {
			return nil, fmt.Errorf("%w: could not convert kid in JWT header to string", errKID)
		}

		// Get the JSONKey.
		jsonKey, err := j.getKey(kid)
		if err != nil {
			return nil, err
		}

		// Determine the key's algorithm and return the appropriate public key.
		switch keyAlg := token.Header["alg"]; keyAlg {
		case ES256, ES384, ES512:
			return jsonKey.getECDSA()
		case PS256, PS384, PS512, RS256, RS384, RS512:
			return jsonKey.getRSA()
		default:
			return nil, fmt.Errorf("%w: %s: feel free to add a feature request or contribute to https://github.com/MicahParks/keyfunc", errUnsupportedKeyType, keyAlg)
		}
	}
}

// downloadKeySet loads the JWKs at the given URL.
func (j *KeySet) downloadKeySet() (err error) {
	// Apply some defaults if options were not provided.
	if j.client == nil {
		j.client = http.DefaultClient
	}

	// Get the keys for the JWKs.
	if err = j.refresh(); err != nil {
		return err
	}

	// Check to see if a background refresh of the JWKs should happen.
	if j.Config.KeyRefreshInterval != nil || j.Config.KeyRefreshRateLimit != nil {
		// Attach a context used to end the background goroutine.
		j.ctx, j.cancel = context.WithCancel(context.Background())

		// Create a channel that will accept requests to refresh the JWKs.
		j.refreshRequests = make(chan context.CancelFunc, 1)

		// Start the background goroutine for data refresh.
		go j.startRefreshing()
	}

	return nil
}

// New creates a new JWKs from a raw JSON message.
func parseKeySet(jwksBytes json.RawMessage) (keys map[string]*rawJWK, err error) {
	// Turn the raw JWKs into the correct Go type.
	var rawKS rawJWKs
	if err = json.Unmarshal(jwksBytes, &rawKS); err != nil {
		return nil, err
	}

	// Iterate through the keys in the raw JWKs. Add them to the JWKs.
	keys = make(map[string]*rawJWK, len(rawKS.Keys))
	for _, key := range rawKS.Keys {
		key := key
		keys[key.ID] = &key
	}

	return keys, nil
}

// getKey gets the JSONKey from the given KID from the JWKs. It may refresh the JWKs if configured to.
func (j *KeySet) getKey(kid string) (jsonKey *rawJWK, err error) {
	// Get the JSONKey from the JWKs.
	var ok bool
	j.mux.RLock()
	jsonKey, ok = j.Keys[kid]
	j.mux.RUnlock()

	// Check if the key was present.
	if !ok {
		// Check to see if configured to refresh on unknown kid.
		if j.Config.KeyRefreshUnknownKID != nil && *j.Config.KeyRefreshUnknownKID {
			// Create a context for refreshing the JWKs.
			ctx, cancel := context.WithCancel(j.ctx)

			// Refresh the JWKs.
			select {
			case <-j.ctx.Done():
				return
			case j.refreshRequests <- cancel:
			default:

				// If the j.refreshRequests channel is full, return the error early.
				return nil, errKIDNotFound
			}

			// Wait for the JWKs refresh to done.
			<-ctx.Done()

			// Lock the JWKs for async safe use.
			j.mux.RLock()
			defer j.mux.RUnlock()

			// Check if the JWKs refresh contained the requested key.
			if jsonKey, ok = j.Keys[kid]; ok {
				return jsonKey, nil
			}
		}

		return nil, errKIDNotFound
	}

	return jsonKey, nil
}

// startRefreshing is meant to be a separate goroutine that will update the keys in a JWKs over a given interval of
// time.
func (j *KeySet) startRefreshing() {
	// Create some rate limiting assets.
	var lastRefresh time.Time
	var queueOnce sync.Once
	var refreshMux sync.Mutex
	if j.Config.KeyRefreshRateLimit != nil {
		lastRefresh = time.Now().Add(-*j.Config.KeyRefreshRateLimit)
	}

	// Create a channel that will never send anything unless there is a refresh interval.
	refreshInterval := make(<-chan time.Time)

	// Enter an infinite loop that ends when the background ends.
	for {
		// If there is a refresh interval, create the channel for it.
		if j.Config.KeyRefreshInterval != nil {
			refreshInterval = time.After(*j.Config.KeyRefreshInterval)
		}

		// Wait for a refresh to occur or the background to end.
		select {

		// Send a refresh request the JWKs after the given interval.
		case <-refreshInterval:
			select {
			case <-j.ctx.Done():
				return
			case j.refreshRequests <- func() {}:
			default: // If the j.refreshRequests channel is full, don't don't send another request.
			}

		// Accept refresh requests.
		case cancel := <-j.refreshRequests:
			// Rate limit, if needed.
			refreshMux.Lock()
			if j.Config.KeyRefreshRateLimit != nil && lastRefresh.Add(*j.Config.KeyRefreshRateLimit).After(time.Now()) {
				// Don't make the JWT parsing goroutine wait for the JWKs to refresh.
				cancel()

				// Only queue a refresh once.
				queueOnce.Do(func() {

					// Launch a goroutine that will get a reservation for a JWKs refresh or fail to and immediately return.
					go func() {
						// Wait for the next time to refresh.
						refreshMux.Lock()
						wait := time.Until(lastRefresh.Add(*j.Config.KeyRefreshRateLimit))
						refreshMux.Unlock()
						select {
						case <-j.ctx.Done():
							return
						case <-time.After(wait):
						}

						// Refresh the JWKs.
						refreshMux.Lock()
						defer refreshMux.Unlock()
						if err := j.refresh(); err != nil && j.Config.KeyRefreshErrorHandler != nil {
							j.Config.KeyRefreshErrorHandler(j, err)
						} else if err == nil && j.Config.KeyRefreshSuccessHandler != nil {
							j.Config.KeyRefreshSuccessHandler(j)
						}

						// Reset the last time for the refresh to now.
						lastRefresh = time.Now()

						// Allow another queue.
						queueOnce = sync.Once{}
					}()
				})
			} else {
				// Refresh the JWKs.
				if err := j.refresh(); err != nil && j.Config.KeyRefreshErrorHandler != nil {
					j.Config.KeyRefreshErrorHandler(j, err)
				} else if err == nil && j.Config.KeyRefreshSuccessHandler != nil {
					j.Config.KeyRefreshSuccessHandler(j)
				}

				// Reset the last time for the refresh to now.
				lastRefresh = time.Now()

				// Allow the JWT parsing goroutine to continue with the refreshed JWKs.
				cancel()
			}
			refreshMux.Unlock()

		// Clean up this goroutine when its context expires.
		case <-j.ctx.Done():
			return
		}
	}
}

// refresh does an HTTP GET on the JWKs URLs in parallel to rebuild the JWKs.
func (j *KeySet) refresh() (err error) {
	// Create a context for the request.
	var ctx context.Context
	var cancel context.CancelFunc
	if j.ctx != nil {
		ctx, cancel = context.WithTimeout(j.ctx, *j.Config.KeyRefreshTimeout)
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), *j.Config.KeyRefreshTimeout)
	}
	defer cancel()

	// Create the HTTP request.
	var keys map[string]*rawJWK
	for _, url := range j.Config.KeySetURLs {
		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, bytes.NewReader(nil)); err != nil {
			return err
		}

		// Get the JWKs as JSON from the given URL.
		var resp *http.Response
		if resp, err = j.client.Do(req); err != nil {
			return err
		}

		// Read the raw JWKs from the body of the response.
		var jwksBytes []byte
		if jwksBytes, err = io.ReadAll(resp.Body); err != nil {
			if cErr := resp.Body.Close(); cErr != nil {
				log.Printf("error closing response body: %s", cErr.Error())
			}
			return err
		}
		if cErr := resp.Body.Close(); cErr != nil {
			log.Printf("error closing response body: %s", cErr.Error())
		}

		// Create an updated JWKs.
		if urlKeys, urlErr := parseKeySet(jwksBytes); urlErr != nil {
			return urlErr
		} else if urlKeys != nil {
			keys = mergemap(keys, urlKeys)
		}
	}

	// Lock the JWKs for async safe usage.
	j.mux.Lock()
	defer j.mux.Unlock()

	// Update the keys.
	j.Keys = keys

	return nil
}

// StopRefreshing ends the background goroutine to update the JWKs. It can only happen once and is only effective if the
// JWKs has a background goroutine refreshing the JWKs keys.
func (j *KeySet) StopRefreshing() {
	if j.cancel != nil {
		j.cancel()
	}
}

// creates a new map with values of origMap overwritten by those in newMap
func mergemap(origMap, newMap map[string]*rawJWK) map[string]*rawJWK {
	var mp map[string]*rawJWK
	if len(origMap) > 0 || len(newMap) > 0 {
		mp = make(map[string]*rawJWK)
	}
	for k, v := range origMap {
		mp[k] = v
	}
	for k, v := range newMap {
		mp[k] = v
	}
	return mp
}
