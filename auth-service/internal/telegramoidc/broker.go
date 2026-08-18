// Package telegramoidc implements a confidential OIDC broker between Kratos
// and Telegram. Kratos only sees broker-issued RS256 tokens and therefore
// never downloads Telegram's mixed-algorithm JWKS.
package telegramoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hardy/kratos-poc2/auth-service/internal/config"
	"github.com/hardy/kratos-poc2/auth-service/internal/store"
	"github.com/hardy/kratos-poc2/auth-service/internal/token"
)

const (
	telegramIssuer = "https://oauth.telegram.org"
	telegramAuth   = telegramIssuer + "/auth"
	telegramToken  = telegramIssuer + "/token"
	telegramJWKS   = telegramIssuer + "/.well-known/jwks.json"
)

type Broker struct {
	cfg    *config.Config
	store  *store.Store
	signer *token.Signer
	client *http.Client
}

func New(cfg *config.Config, st *store.Store, signer *token.Signer) *Broker {
	return &Broker{cfg: cfg, store: st, signer: signer, client: &http.Client{Timeout: 10 * time.Second}}
}

func (b *Broker) Register(app *fiber.App) {
	app.Get("/oidc/telegram/authorize", b.Authorize)
	app.Get("/oidc/telegram/callback", b.Callback)
	app.Get("/internal/oidc/telegram/.well-known/openid-configuration", b.Discovery)
	app.Post("/internal/oidc/telegram/token", b.Token)
	app.Get("/internal/oidc/telegram/jwks.json", b.JWKS)
}

func (b *Broker) Discovery(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"issuer":                                b.cfg.TelegramBrokerIssuer,
		"authorization_endpoint":                strings.TrimRight(b.cfg.TelegramBrokerPublicBaseURL, "/") + "/oidc/telegram/authorize",
		"token_endpoint":                        b.cfg.TelegramBrokerIssuer + "/token",
		"jwks_uri":                              b.cfg.TelegramBrokerIssuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "phone"},
	})
}

func (b *Broker) JWKS(c *fiber.Ctx) error {
	body, err := b.signer.JWKSJSON()
	if err != nil {
		return oauthError(c, http.StatusInternalServerError, "server_error", "unable to encode JWKS")
	}
	c.Type("json")
	return c.Send(body)
}

func (b *Broker) Authorize(c *fiber.Ctx) error {
	q := c.Queries()
	if q["response_type"] != "code" || q["client_id"] != b.cfg.TelegramBrokerClientID ||
		q["redirect_uri"] != b.cfg.TelegramBrokerRedirectURL || q["state"] == "" ||
		!hasScope(q["scope"], "openid") ||
		q["code_challenge_method"] != "S256" || q["code_challenge"] == "" {
		return oauthError(c, http.StatusBadRequest, "invalid_request", "invalid authorization request")
	}

	upstreamState, err := randomURLValue(32)
	if err != nil {
		return oauthError(c, http.StatusInternalServerError, "server_error", "unable to create state")
	}
	verifier, err := randomURLValue(48)
	if err != nil {
		return oauthError(c, http.StatusInternalServerError, "server_error", "unable to create PKCE verifier")
	}
	nonce, err := randomURLValue(32)
	if err != nil {
		return oauthError(c, http.StatusInternalServerError, "server_error", "unable to create nonce")
	}
	if err := b.store.SaveBrokerAuthorization(c.Context(), store.BrokerAuthorization{
		UpstreamState: upstreamState, ClientID: q["client_id"], RedirectURI: q["redirect_uri"], ClientState: q["state"],
		Scope: q["scope"], Nonce: q["nonce"], UpstreamNonce: nonce, CodeChallenge: q["code_challenge"], CodeMethod: q["code_challenge_method"], CodeVerifier: verifier,
	}); err != nil {
		return oauthError(c, http.StatusInternalServerError, "server_error", "unable to persist authorization request")
	}

	u, _ := url.Parse(telegramAuth)
	params := u.Query()
	params.Set("client_id", b.cfg.TelegramOIDCClientID)
	params.Set("redirect_uri", strings.TrimRight(b.cfg.TelegramBrokerPublicBaseURL, "/")+"/oidc/telegram/callback")
	params.Set("response_type", "code")
	params.Set("scope", allowedScopes(q["scope"]))
	params.Set("state", upstreamState)
	params.Set("nonce", nonce)
	params.Set("code_challenge", pkceChallenge(verifier))
	params.Set("code_challenge_method", "S256")
	u.RawQuery = params.Encode()
	return c.Redirect(u.String(), http.StatusFound)
}

func (b *Broker) Callback(c *fiber.Ctx) error {
	rec, err := b.store.ConsumeBrokerAuthorization(c.Context(), c.Query("state"))
	if err != nil {
		return oauthError(c, http.StatusBadRequest, "invalid_request", "unknown or expired authorization state")
	}
	if upstreamErr := c.Query("error"); upstreamErr != "" {
		return redirectError(c, rec, upstreamErr, c.Query("error_description"))
	}
	code := c.Query("code")
	if code == "" {
		return redirectError(c, rec, "invalid_request", "Telegram callback omitted code")
	}
	upstreamToken, err := b.exchangeTelegramCode(c.Context(), code, rec.CodeVerifier)
	if err != nil {
		log.Printf("Telegram OIDC token exchange failed: %v", err)
		return redirectError(c, rec, "access_denied", "Telegram token exchange failed")
	}
	claims, err := b.validateTelegramIDToken(upstreamToken.IDToken, rec.UpstreamNonce)
	if err != nil {
		return redirectError(c, rec, "access_denied", "Telegram ID token validation failed")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return redirectError(c, rec, "access_denied", "Telegram ID token omitted subject")
	}
	brokerCode, err := randomURLValue(32)
	if err != nil {
		return redirectError(c, rec, "server_error", "unable to create authorization code")
	}
	if err := b.store.SaveBrokerCode(c.Context(), store.BrokerCode{
		Code: brokerCode, ClientID: rec.ClientID, RedirectURI: rec.RedirectURI, CodeChallenge: rec.CodeChallenge,
		CodeMethod: rec.CodeMethod, Nonce: rec.Nonce, Subject: sub, Claims: profileClaims(claims),
	}); err != nil {
		return redirectError(c, rec, "server_error", "unable to persist authorization code")
	}
	u, _ := url.Parse(rec.RedirectURI)
	q := u.Query()
	q.Set("code", brokerCode)
	q.Set("state", rec.ClientState)
	u.RawQuery = q.Encode()
	return c.Redirect(u.String(), http.StatusFound)
}

func (b *Broker) Token(c *fiber.Ctx) error {
	clientID, clientSecret, ok := basicAuth(c.Get(fiber.HeaderAuthorization))
	if !ok {
		clientID, clientSecret = c.FormValue("client_id"), c.FormValue("client_secret")
	}
	if clientID != b.cfg.TelegramBrokerClientID || clientSecret == "" ||
		!constantTimeEqual(clientSecret, b.cfg.TelegramBrokerClientSecret) {
		c.Set(fiber.HeaderWWWAuthenticate, `Basic realm="telegram-broker"`)
		return oauthError(c, http.StatusUnauthorized, "invalid_client", "client authentication failed")
	}
	if c.FormValue("grant_type") != "authorization_code" || c.FormValue("code") == "" ||
		c.FormValue("redirect_uri") != b.cfg.TelegramBrokerRedirectURL {
		return oauthError(c, http.StatusBadRequest, "invalid_request", "invalid token request")
	}
	rec, err := b.store.ConsumeBrokerCode(c.Context(), c.FormValue("code"), clientID)
	if err != nil || rec.RedirectURI != c.FormValue("redirect_uri") || rec.CodeMethod != "S256" ||
		!constantTimeEqual(pkceChallenge(c.FormValue("code_verifier")), rec.CodeChallenge) {
		return oauthError(c, http.StatusBadRequest, "invalid_grant", "invalid authorization code or PKCE verifier")
	}
	idToken, exp, err := b.signer.SignOIDC(rec.Subject, b.cfg.TelegramBrokerIssuer, clientID, rec.Nonce, rec.Claims)
	if err != nil {
		return oauthError(c, http.StatusInternalServerError, "server_error", "unable to issue ID token")
	}
	// oauth2 clients expect access_token even when this relying party uses only
	// claims_source: id_token. This opaque value grants no API access.
	accessToken, err := randomURLValue(32)
	if err != nil {
		return oauthError(c, http.StatusInternalServerError, "server_error", "unable to issue access token")
	}
	return c.JSON(fiber.Map{
		"token_type":   "Bearer",
		"access_token": accessToken,
		"id_token":     idToken,
		"expires_in":   int(time.Until(exp).Seconds()),
	})
}

type telegramTokenResponse struct {
	IDToken string `json:"id_token"`
}

func (b *Broker) exchangeTelegramCode(ctx context.Context, code, verifier string) (*telegramTokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {strings.TrimRight(b.cfg.TelegramBrokerPublicBaseURL, "/") + "/oidc/telegram/callback"},
		"client_id":     {b.cfg.TelegramOIDCClientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, telegramToken, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(b.cfg.TelegramOIDCClientID, b.cfg.TelegramOIDCClientSecret)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram token endpoint returned %d", resp.StatusCode)
	}
	var out telegramTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.IDToken == "" {
		return nil, fmt.Errorf("invalid Telegram token response")
	}
	return &out, nil
}

func (b *Broker) validateTelegramIDToken(raw, expectedNonce string) (jwt.MapClaims, error) {
	key, err := b.telegramKey(raw)
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected Telegram signing method")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(telegramIssuer), jwt.WithAudience(b.cfg.TelegramOIDCClientID))
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid Telegram ID token: %w", err)
	}
	if expectedNonce != "" && !constantTimeEqual(claimString(claims, "nonce"), expectedNonce) {
		return nil, fmt.Errorf("Telegram ID token nonce mismatch")
	}
	return claims, nil
}

func (b *Broker) telegramKey(raw string) (*rsa.PublicKey, error) {
	parser := jwt.NewParser()
	unverified := jwt.MapClaims{}
	t, _, err := parser.ParseUnverified(raw, unverified)
	if err != nil || t.Header["alg"] != jwt.SigningMethodRS256.Alg() {
		return nil, fmt.Errorf("invalid Telegram ID token header")
	}
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("Telegram ID token omitted kid")
	}
	resp, err := b.client.Get(telegramJWKS)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Telegram JWKS endpoint returned %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	for _, jwk := range doc.Keys {
		// Telegram publishes an unsupported ES256K key as well. Only accept the
		// selected RSA/RS256 key; never attempt to parse other key types.
		if jwk.Kid != kid || jwk.Kty != "RSA" || jwk.Alg != "RS256" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, fmt.Errorf("matching Telegram RSA JWK not found")
}

func redirectError(c *fiber.Ctx, rec *store.BrokerAuthorization, code, description string) error {
	u, _ := url.Parse(rec.RedirectURI)
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	q.Set("state", rec.ClientState)
	u.RawQuery = q.Encode()
	return c.Redirect(u.String(), http.StatusFound)
}

func oauthError(c *fiber.Ctx, status int, code, description string) error {
	return c.Status(status).JSON(fiber.Map{"error": code, "error_description": description})
}

func randomURLValue(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func basicAuth(header string) (string, string, bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return "", "", false
	}
	clientID, secret, ok := strings.Cut(string(raw), ":")
	return clientID, secret, ok
}

func hasScope(scope, wanted string) bool {
	for _, s := range strings.Fields(scope) {
		if s == wanted {
			return true
		}
	}
	return false
}

func allowedScopes(scope string) string {
	out := []string{"openid"}
	for _, s := range strings.Fields(scope) {
		if s == "profile" || s == "phone" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

func claimString(c jwt.MapClaims, key string) string {
	v, _ := c[key].(string)
	return v
}

func profileClaims(in jwt.MapClaims) map[string]any {
	out := make(map[string]any)
	for _, key := range []string{"id", "name", "given_name", "family_name", "preferred_username", "picture", "phone_number"} {
		if value, ok := in[key]; ok {
			out[key] = value
		}
	}
	return out
}
