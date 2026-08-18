package telegramoidc

import "testing"

func TestPKCEChallenge(t *testing.T) {
	// RFC 7636 appendix B verifier and expected S256 challenge.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceChallenge(verifier); got != expected {
		t.Fatalf("PKCE challenge = %q, want %q", got, expected)
	}
}

func TestBrokerScopes(t *testing.T) {
	if !hasScope("profile openid phone", "openid") {
		t.Fatal("openid scope was not detected")
	}
	if got := allowedScopes("openid profile arbitrary phone"); got != "openid profile phone" {
		t.Fatalf("allowed scopes = %q", got)
	}
}

func TestBasicAuth(t *testing.T) {
	id, secret, ok := basicAuth("Basic a3JhdG9zOnNlY3JldA==")
	if !ok || id != "kratos" || secret != "secret" {
		t.Fatalf("basic auth parsed as id=%q secret=%q ok=%v", id, secret, ok)
	}
	if _, _, ok := basicAuth("Bearer token"); ok {
		t.Fatal("non-Basic auth was accepted")
	}
}
