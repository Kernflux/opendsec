package e2b

import (
	"net/http"
	"regexp"
	"testing"
)

// TestE2BKey: E2BKey passes the E2B SDKs' format check, and the gateway
// reads the token back from every header it takes one from.
func TestE2BKey(t *testing.T) {
	const tok = "dsk.abc123.Zx-9_secret"
	k := E2BKey(tok)
	if !regexp.MustCompile(`\Ae2b_[0-9a-f]+\z`).MatchString(k) { // e2b/api/__init__.py, Python SDK 2.25 to 2.45
		t.Fatalf("%q fails the SDK's check", k)
	}
	for _, h := range []string{"X-API-KEY", "X-Access-Token", "E2B-Traffic-Access-Token", "Authorization"} {
		r, _ := http.NewRequest("GET", "/", nil)
		v := k
		if h == "Authorization" {
			v = "Bearer " + k
		}
		r.Header.Set(h, v)
		if got := apiKey(r); got != tok {
			t.Errorf("%s: got %q, want %q", h, got, tok)
		}
	}
	// A plain token, and e2b_ keys that are not an encoded token, pass through.
	for _, k := range []string{tok, "e2b_00ff", "e2b_zz", E2BKey("other")} {
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("X-API-KEY", k)
		if got := apiKey(r); got != k {
			t.Errorf("%q: got %q", k, got)
		}
	}
}
