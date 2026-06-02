package auth

import (
	"testing"
	"time"
)

var testSecret = []byte("test-secret-please-ignore-0123456789")

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := SessionClaims{Subject: "user-1", Name: "Alice", Groups: []string{"admins"}}

	tok, err := SignSession(testSecret, in, now, time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	got, err := VerifySession(testSecret, tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "user-1" || got.Name != "Alice" {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "admins" {
		t.Fatalf("groups mismatch: %+v", got.Groups)
	}
	if got.IssuedAt != now.Unix() || got.Expires != now.Add(time.Hour).Unix() {
		t.Fatalf("iat/exp mismatch: iat=%d exp=%d", got.IssuedAt, got.Expires)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tok, _ := SignSession(testSecret, SessionClaims{Subject: "user-1"}, now, time.Hour)

	// Flip a character in the payload segment.
	b := []byte(tok)
	b[len(b)/2] ^= 0x01
	if _, err := VerifySession(testSecret, string(b), now); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tok, _ := SignSession(testSecret, SessionClaims{Subject: "user-1"}, now, time.Hour)

	if _, err := VerifySession([]byte("a-different-secret"), tok, now); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tok, _ := SignSession(testSecret, SessionClaims{Subject: "user-1"}, now, time.Hour)

	if _, err := VerifySession(testSecret, tok, now.Add(2*time.Hour)); err != ErrExpiredToken {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, bad := range []string{"", "a.b", "a.b.c.d", "not-a-token"} {
		if _, err := VerifySession(testSecret, bad, now); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestHasGroup(t *testing.T) {
	cases := []struct {
		groups []string
		want   string
		ok     bool
	}{
		{[]string{"admins", "users"}, "admins", true},
		{[]string{"users"}, "admins", false},
		{nil, "admins", false},
		{[]string{"users"}, "", true}, // empty want = no restriction
		{nil, "", true},
	}
	for _, c := range cases {
		if got := hasGroup(c.groups, c.want); got != c.ok {
			t.Errorf("hasGroup(%v, %q) = %v, want %v", c.groups, c.want, got, c.ok)
		}
	}
}

func TestToStringSlice(t *testing.T) {
	if got := toStringSlice([]any{"a", "b", 3}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("toStringSlice([]any) = %v", got)
	}
	if got := toStringSlice("solo"); len(got) != 1 || got[0] != "solo" {
		t.Fatalf("toStringSlice(string) = %v", got)
	}
	if got := toStringSlice(nil); got != nil {
		t.Fatalf("toStringSlice(nil) = %v", got)
	}
}
