package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config holds everything needed to wire up OIDC against PocketID.
type Config struct {
	IssuerURL     string   // PocketID base URL (OIDC discovery root)
	ClientID      string   // OIDC client id
	ClientSecret  string   // OIDC client secret (confidential client)
	RedirectURL   string   // public URL of …/api/auth/callback
	AllowedGroup  string   // user must be in this group (empty = any authenticated user)
	GroupsClaim   string   // claim that carries group membership (default "groups")
	Scopes        []string // OAuth2 scopes (default openid profile email groups)
	SessionSecret []byte   // HS256 signing key for the app session token
	SessionTTL    time.Duration
}

// Authenticator runs the OIDC Authorization Code flow and mints/validates the
// app's own session tokens. It is safe for concurrent use.
type Authenticator struct {
	verifier      *oidc.IDTokenVerifier
	oauth         *oauth2.Config
	allowedGroup  string
	groupsClaim   string
	sessionSecret []byte
	sessionTTL    time.Duration
	now           func() time.Time
}

// flowCookieName holds the per-login state/nonce/PKCE-verifier between the
// /login redirect and the /callback. It is a short-lived signed cookie, so we
// keep no server-side session store.
const flowCookieName = "oidc_flow"

// flowState is what we stash (signed) in the flow cookie.
type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
}

// New performs OIDC discovery against cfg.IssuerURL and returns a ready
// Authenticator. Returns an error if the issuer is unreachable.
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery (%s): %w", cfg.IssuerURL, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}
	groupsClaim := cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}

	return &Authenticator{
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		allowedGroup:  cfg.AllowedGroup,
		groupsClaim:   groupsClaim,
		sessionSecret: cfg.SessionSecret,
		sessionTTL:    ttl,
		now:           time.Now,
	}, nil
}

// HandleLogin starts the OIDC flow: it stores state/nonce/PKCE in a signed,
// short-lived cookie and redirects the browser to PocketID.
func (a *Authenticator) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state := randToken()
	nonce := randToken()
	verifier := oauth2.GenerateVerifier()

	flow, err := a.signFlow(flowState{State: state, Nonce: nonce, Verifier: verifier})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    flow,
		Path:     "/",
		MaxAge:   600, // 10 minutes to complete the handshake
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
	})

	url := a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// HandleCallback completes the flow: validates state, exchanges the code,
// verifies the ID token + nonce, checks group membership, and on success
// redirects to the SPA callback with the freshly-minted session token in the
// URL fragment (so it never lands in server logs or the Referer header).
func (a *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cookie, err := r.Cookie(flowCookieName)
	if err != nil {
		a.fail(w, r, "session", "missing flow cookie")
		return
	}
	// Clear the one-shot flow cookie regardless of outcome.
	http.SetCookie(w, &http.Cookie{Name: flowCookieName, Path: "/", MaxAge: -1, HttpOnly: true})

	flow, err := a.verifyFlow(cookie.Value)
	if err != nil {
		a.fail(w, r, "session", "bad flow cookie")
		return
	}
	if q := r.URL.Query().Get("state"); q == "" || q != flow.State {
		a.fail(w, r, "session", "state mismatch")
		return
	}
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		a.fail(w, r, "auth", "provider error: "+errCode)
		return
	}

	oauth2Token, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		a.fail(w, r, "auth", "code exchange failed")
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		a.fail(w, r, "auth", "no id_token in response")
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		a.fail(w, r, "auth", "id_token verify failed")
		return
	}
	if idToken.Nonce != flow.Nonce {
		a.fail(w, r, "auth", "nonce mismatch")
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		a.fail(w, r, "auth", "claims parse failed")
		return
	}
	groups := toStringSlice(claims[a.groupsClaim])
	if !hasGroup(groups, a.allowedGroup) {
		log.Printf("auth: denied %q — not in group %q", stringClaim(claims, "sub"), a.allowedGroup)
		a.fail(w, r, "forbidden", "user not in allowed group")
		return
	}

	session, err := SignSession(a.sessionSecret, SessionClaims{
		Subject: stringClaim(claims, "sub"),
		Name:    firstNonEmpty(stringClaim(claims, "name"), stringClaim(claims, "preferred_username")),
		Email:   stringClaim(claims, "email"),
		Groups:  groups,
	}, a.now(), a.sessionTTL)
	if err != nil {
		a.fail(w, r, "auth", "session sign failed")
		return
	}

	// Token in the fragment — read client-side by /auth/callback, never sent
	// to a server or logged.
	http.Redirect(w, r, "/auth/callback#token="+session, http.StatusFound)
}

// HandleLogout clears the flow cookie. The session token itself is stateless
// and lives in the browser; the SPA drops it locally. Returns 204.
func (a *Authenticator) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: flowCookieName, Path: "/", MaxAge: -1, HttpOnly: true})
	w.WriteHeader(http.StatusNoContent)
}

// HandleMe returns the current session's claims as JSON. It assumes the auth
// middleware has already validated the request.
func (a *Authenticator) HandleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := a.ValidateSession(extractBearer(r))
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":    claims.Subject,
		"name":   claims.Name,
		"email":  claims.Email,
		"groups": claims.Groups,
		"exp":    claims.Expires,
	})
}

// ValidateSession verifies an app session token and returns its claims. Used by
// the server middleware to authorize API/WebSocket requests.
func (a *Authenticator) ValidateSession(token string) (*SessionClaims, bool) {
	if token == "" {
		return nil, false
	}
	claims, err := VerifySession(a.sessionSecret, token, a.now())
	if err != nil {
		return nil, false
	}
	return claims, true
}

// fail clears any half-done state and bounces the browser back to the login
// page with an error code the SPA can render.
func (a *Authenticator) fail(w http.ResponseWriter, r *http.Request, code, detail string) {
	log.Printf("auth: callback failed (%s): %s", code, detail)
	http.Redirect(w, r, "/login?error="+code, http.StatusFound)
}

// --- flow cookie signing (reuses the HS256 helper) ---

func (a *Authenticator) signFlow(f flowState) (string, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	payload := b64.EncodeToString(raw)
	sig := b64.EncodeToString(hmacSHA256(a.sessionSecret, payload))
	return payload + "." + sig, nil
}

func (a *Authenticator) verifyFlow(v string) (flowState, error) {
	var f flowState
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return f, ErrInvalidToken
	}
	expected := b64.EncodeToString(hmacSHA256(a.sessionSecret, parts[0]))
	if expected != parts[1] {
		return f, ErrInvalidToken
	}
	raw, err := b64.DecodeString(parts[0])
	if err != nil {
		return f, ErrInvalidToken
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, ErrInvalidToken
	}
	return f, nil
}

// --- helpers ---

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func extractBearer(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.URL.Query().Get("token")
}

func toStringSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{x}
	default:
		return nil
	}
}

func stringClaim(claims map[string]any, key string) string {
	if s, ok := claims[key].(string); ok {
		return s
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
