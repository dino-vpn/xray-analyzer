// Package auth implements OIDC (PocketID) browser login with group-based
// access control. After a successful OIDC handshake the backend mints its own
// signed session token (see session.go) which the frontend stores and sends as
// a Bearer token — reusing the existing token transport unchanged.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// SessionClaims is the payload of an app-issued session token. It is minted
// after OIDC login succeeds and the group check passes, then verified on every
// subsequent API request in place of the old static token.
type SessionClaims struct {
	Subject  string   `json:"sub"`
	Name     string   `json:"name,omitempty"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	IssuedAt int64    `json:"iat"`
	Expires  int64    `json:"exp"`
}

var (
	// ErrInvalidToken covers any malformed/tampered/badly-signed token.
	ErrInvalidToken = errors.New("invalid session token")
	// ErrExpiredToken is returned when a structurally valid token is past exp.
	ErrExpiredToken = errors.New("session token expired")
)

// b64 is the URL-safe, unpadded base64 used for the token segments (JWT-style).
var b64 = base64.RawURLEncoding

// SignSession produces a compact HS256 token "header.payload.signature" signed
// with secret. iat/exp are filled in from now and ttl. Kept self-contained
// (stdlib HMAC) so we don't pull in a JWT library for a token we fully control.
func SignSession(secret []byte, claims SessionClaims, now time.Time, ttl time.Duration) (string, error) {
	claims.IssuedAt = now.Unix()
	claims.Expires = now.Add(ttl).Unix()

	header := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := b64.EncodeToString(payloadJSON)

	signingInput := header + "." + payload
	sig := b64.EncodeToString(hmacSHA256(secret, signingInput))
	return signingInput + "." + sig, nil
}

// VerifySession checks the signature and expiry of a token and returns its
// claims. now is passed in so callers (and tests) control the clock.
func VerifySession(secret []byte, token string, now time.Time) (*SessionClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]
	expectedSig := hmacSHA256(secret, signingInput)

	gotSig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	// Constant-time compare to avoid signature timing oracles.
	if subtle.ConstantTimeCompare(gotSig, expectedSig) != 1 {
		return nil, ErrInvalidToken
	}

	payloadJSON, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims SessionClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if claims.Expires > 0 && now.Unix() >= claims.Expires {
		return nil, ErrExpiredToken
	}
	return &claims, nil
}

// hasGroup reports whether groups contains want. An empty want means "no group
// restriction" and always passes.
func hasGroup(groups []string, want string) bool {
	if want == "" {
		return true
	}
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}

func hmacSHA256(secret []byte, input string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return mac.Sum(nil)
}
