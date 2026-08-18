package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/hardy/kratos-poc2/auth-service/internal/config"
	"github.com/hardy/kratos-poc2/auth-service/internal/httpapi/cookies"
	"github.com/hardy/kratos-poc2/auth-service/internal/kratosx"
	"github.com/hardy/kratos-poc2/auth-service/internal/sessionmerge"
	"github.com/hardy/kratos-poc2/auth-service/internal/store"
	"github.com/hardy/kratos-poc2/auth-service/internal/telegramoidc"
	"github.com/hardy/kratos-poc2/auth-service/internal/token"
)

func oidcUpstreamParams(provider, intent string) map[string]string {
	if provider != "google" {
		return nil
	}
	switch intent {
	case "register", "link":
		return map[string]string{"prompt": "consent"}
	default:
		return map[string]string{"prompt": "select_account"}
	}
}

func ensureOAuthPrompt(redirectURL, prompt string) string {
	if prompt == "" || redirectURL == "" {
		return redirectURL
	}
	u, err := url.Parse(redirectURL)
	if err != nil {
		return redirectURL
	}
	q := u.Query()
	if q.Get("prompt") != "" {
		return redirectURL
	}
	q.Set("prompt", prompt)
	u.RawQuery = q.Encode()
	return u.String()
}

func oauthPromptFromURL(redirectURL string) string {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("prompt")
}

// telegramOAuthStateMaxLen is enforced by oauth.telegram.org (plain-text "state too long" if exceeded).
const telegramOAuthStateMaxLen = 256

func shortenTelegramOIDCRedirect(ctx context.Context, st *store.Store, redirectURL string) (string, int, int, error) {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return redirectURL, 0, 0, err
	}
	fullState := u.Query().Get("state")
	if fullState == "" || len(fullState) <= telegramOAuthStateMaxLen {
		return redirectURL, len(fullState), len(fullState), nil
	}
	short := strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := st.SaveOIDCState(ctx, store.OIDCStateRecord{
		ShortState:  short,
		KratosState: fullState,
	}); err != nil {
		return "", len(fullState), 0, err
	}
	q := u.Query()
	q.Set("state", short)
	u.RawQuery = q.Encode()
	return u.String(), len(fullState), len(short), nil
}

func expandTelegramCallbackURL(ctx context.Context, st *store.Store, targetURL string) (string, bool, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL, false, err
	}
	shortState := u.Query().Get("state")
	if shortState == "" {
		return targetURL, false, nil
	}
	fullState, err := st.ConsumeOIDCState(ctx, shortState)
	if err != nil {
		return targetURL, false, nil
	}
	q := u.Query()
	q.Set("state", fullState)
	u.RawQuery = q.Encode()
	return u.String(), true, nil
}

type Server struct {
	cfg     *config.Config
	kratos  *kratosx.Client
	store   *store.Store
	signer  *token.Signer
	log     *logrus.Logger
	lastOTP sync.Map
	webDir  string
}

func New(cfg *config.Config, kratos *kratosx.Client, st *store.Store, signer *token.Signer, log *logrus.Logger, webDir string) *Server {
	return &Server{cfg: cfg, kratos: kratos, store: st, signer: signer, log: log, webDir: webDir}
}

func (s *Server) Listen() error {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ProxyHeader:           "X-Forwarded-Proto",
	})
	app.Use(s.cors())

	app.Get("/.well-known/jwks.json", s.handleJWKS)
	telegramoidc.New(s.cfg, s.store, s.signer).Register(app)
	app.Post("/internal/courier", s.handleCourier)

	app.Get("/api/v1/session", s.handleSession)
	app.Get("/api/v1/debug/session", s.handleDebugSession)
	app.Get("/api/v1/debug/identity", s.handleDebugIdentity)
	app.Get("/api/v1/debug/last-otp", s.handleLastOTP)
	app.Get("/api/v1/debug/auth-state", s.handleDebugAuthState)
	app.Get("/api/v1/auth/error", s.handleAuthError)
	app.Get("/api/v1/auth/oidc/return", s.handleOIDCReturn)
	app.Get("/api/v1/auth/oidc/stepup/done", s.handleOIDCStepUpDone)
	app.Post("/api/v1/policy/demo-sensitive", s.handlePolicyDemoSensitive)

	auth := app.Group("/api/v1/auth")
	auth.Post("/email-otp/start", s.handleEmailOTPStart)
	auth.Post("/email-otp/verify", s.handleEmailOTPVerify)
	auth.Post("/passkey/register/start", s.handlePasskeyRegisterStart)
	auth.Post("/passkey/register/finish", s.handlePasskeyRegisterFinish)
	auth.Post("/passkey/login/start", s.handlePasskeyLoginStart)
	auth.Post("/passkey/login/finish", s.handlePasskeyLoginFinish)
	auth.Post("/oidc/:provider/start", s.handleOIDCStart)
	auth.Get("/methods", s.handleMethods)
	auth.Post("/methods/passkey/start", s.handlePasskeyLinkStart)
	auth.Post("/methods/passkey/finish", s.handlePasskeyLinkFinish)
	auth.Delete("/methods/passkey/:id", s.handlePasskeyRemove)
	auth.Post("/methods/email-otp/start", s.handleEmailOTPLinkStart)
	auth.Post("/methods/email-otp/verify", s.handleEmailOTPLinkVerify)
	auth.Delete("/methods/oidc/:provider", s.handleOIDCUnlink)
	auth.Post("/2fa/totp/start", s.handleTOTPStart)
	auth.Post("/2fa/totp/confirm", s.handleTOTPConfirm)
	auth.Delete("/2fa/totp", s.handleTOTPDelete)
	auth.Post("/stepup/aal2/start", s.handleStepUpAAL2Start)
	auth.Post("/stepup/aal2/totp", s.handleStepUpAAL2TOTP)
	auth.Post("/stepup/passkey/start", s.handleStepUpPasskeyStart)
	auth.Post("/stepup/passkey/finish", s.handlePasskeyLoginFinish)
	auth.Post("/stepup/email-otp/start", s.handleStepUpEmailOTPStart)
	auth.Post("/stepup/email-otp/verify", s.handleStepUpEmailOTPVerify)
	auth.Post("/stepup/google/start", s.handleStepUpGoogleStart)
	auth.Post("/stepup/refresh/start", s.handleStepUpRefreshStart)
	auth.Post("/logout", s.handleLogout)
	auth.Delete("/account", s.handleDeleteAccount)

	app.All("/auth/kratos/*", s.proxyKratos)
	app.Static("/", s.webDir)

	s.log.Infof("listening on %s", s.cfg.ListenAddr)
	return app.Listen(s.cfg.ListenAddr)
}

func (s *Server) cors() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("Access-Control-Allow-Origin", s.cfg.PublicBaseURL)
		c.Set("Access-Control-Allow-Credentials", "true")
		c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Token")
		c.Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		if c.Method() == fiber.MethodOptions {
			return c.SendStatus(fiber.StatusNoContent)
		}
		return c.Next()
	}
}

func (s *Server) kratosToken(c *fiber.Ctx) string {
	if t := cookies.SessionTokenFromFiber(c); t != "" {
		return t
	}
	return c.Get("X-Session-Token")
}

func (s *Server) persistSessionToken(c *fiber.Ctx, res *kratosx.SubmitResult) {
	if t := kratosx.ExtractSessionToken(res); t != "" {
		cookies.SetSessionToken(c, s.cfg.PublicBaseURL, t)
	}
}

func (s *Server) handleJWKS(c *fiber.Ctx) error {
	b, err := s.signer.JWKSJSON()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(b)
}

func (s *Server) handleCourier(c *fiber.Ctx) error {
	auth := c.Get("Authorization")
	if auth != "Bearer "+s.cfg.CourierWebhookSecret {
		return c.SendStatus(fiber.StatusUnauthorized)
	}
	var payload map[string]any
	if err := c.BodyParser(&payload); err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}
	s.log.WithField("courier", payload).Info("courier message")
	if recipient, ok := payload["recipient"].(string); ok {
		s.lastOTP.Store(recipient, payload)
		latest := map[string]any{"recipient": recipient}
		for k, v := range payload {
			latest[k] = v
		}
		s.lastOTP.Store("_latest", latest)
		if code := otpFromPayload(payload); code != "" {
			s.log.WithFields(logrus.Fields{
				"flow":      "courier_otp",
				"recipient": recipient,
				"otp_code":  code,
				"type":      otpCodeType(payload),
			}).Info("OTP code (use for verify)")
		}
	}
	return c.SendStatus(fiber.StatusOK)
}

func (s *Server) handleLastOTP(c *fiber.Ctx) error {
	email := strings.TrimSpace(c.Query("email"))
	useLatest := c.Query("latest") == "1" || c.Query("latest") == "true"

	var payload map[string]any
	if email != "" {
		if v, ok := s.lastOTP.Load(email); ok {
			payload, _ = v.(map[string]any)
		}
	}
	if payload == nil && (useLatest || email == "") {
		if v, ok := s.lastOTP.Load("_latest"); ok {
			payload, _ = v.(map[string]any)
		}
	}
	if payload == nil {
		return c.JSON(fiber.Map{})
	}
	out := fiber.Map{}
	for k, val := range payload {
		out[k] = val
	}
	out["code"] = otpFromPayload(payload)
	out["code_type"] = otpCodeType(payload)
	return c.JSON(out)
}

func (s *Server) handleAuthError(c *fiber.Ctx) error {
	id := c.Query("id")
	logFields := logrus.Fields{
		"flow":     "kratos_error",
		"error_id": id,
		"query":    c.Queries(),
	}
	s.log.WithFields(logFields).Warn("kratos self-service error redirect")
	return c.Redirect("/?oidc_error=kratos_" + id)
}

func (s *Server) saveFlowRef(ctx context.Context, kind kratosx.FlowKind, flow *kratosx.FlowResponse, email, username string) (string, error) {
	ref := uuid.NewString()
	rec := store.FlowRecord{
		FlowRef:      ref,
		KratosFlowID: flow.ID,
		Kind:         string(kind),
		Email:        email,
		Username:     username,
	}
	if err := s.store.SaveFlow(ctx, rec); err != nil {
		return "", err
	}
	return ref, nil
}

func (s *Server) handleDebugAuthState(c *fiber.Ctx) error {
	token := s.kratosToken(c)
	state := fiber.Map{
		"host":            c.Hostname(),
		"protocol":        c.Protocol(),
		"forwarded_proto": c.Get("X-Forwarded-Proto"),
		"cookie_present":  token != "",
		"cookie_len":      len(token),
	}
	if token != "" {
		if session, err := s.kratos.WhoAmI(c.Context(), token); err == nil {
			state["whoami_ok"] = true
			state["identity_id"] = session.Identity.ID
			state["session_id"] = session.ID
		} else {
			state["whoami_ok"] = false
			state["whoami_error"] = err.Error()
		}
	}
	return c.JSON(state)
}

func (s *Server) sessionResponse(c *fiber.Ctx) error {
	sessionToken := s.kratosToken(c)
	if sessionToken == "" {
		s.log.WithFields(logrus.Fields{
			"flow":            "session",
			"host":            c.Hostname(),
			"forwarded_proto": c.Get("X-Forwarded-Proto"),
			"cookie_present":  false,
		}).Debug("session check: no cookie")
		return c.JSON(fiber.Map{"authenticated": false})
	}
	session, err := s.kratos.WhoAmI(c.Context(), sessionToken)
	if err != nil {
		s.log.WithFields(logrus.Fields{
			"flow":         "session",
			"host":         c.Hostname(),
			"cookie_len":   len(sessionToken),
			"whoami_error": err.Error(),
		}).Warn("session check: whoami failed")
		return c.JSON(fiber.Map{"authenticated": false})
	}
	user, err := s.store.GetOrCreateUser(c.Context(), session.Identity.ID, kratosx.PrimaryContact(session.Identity.Traits))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	admin, _ := s.kratos.GetAdminIdentity(c.Context(), session.Identity.ID)
	linked := kratosx.AggregateLinkedMethods(admin)
	for _, m := range linked {
		switch m {
		case "google":
			if sub := oidcSubject(admin, "google"); sub != "" {
				_ = s.store.PutIdentifier(c.Context(), "GOOGLE", sub, user.UserID)
			}
		case "telegram":
			if tid := kratosx.TraitString(session.Identity.Traits, "telegram_id"); tid != "" {
				_ = s.store.PutIdentifier(c.Context(), "TELEGRAM", tid, user.UserID)
			}
		case "email_otp":
			if email := kratosx.TraitString(session.Identity.Traits, "email"); email != "" {
				_ = s.store.PutIdentifier(c.Context(), "EMAIL", email, user.UserID)
			}
		}
	}
	amr := kratosx.MethodsUsed(session)
	traitsEmail := kratosx.TraitString(session.Identity.Traits, "email")
	traitsUsername := kratosx.TraitString(session.Identity.Traits, "username")
	claims := token.Claims{
		KratosIdentityID: session.Identity.ID,
		AAL:              session.AuthenticatorAssuranceLevel,
		AMR:              amr,
		LinkedMethods:    linked,
		Email:            traitsEmail,
		GoogleEmail:      kratosx.TraitString(session.Identity.Traits, "google_email"),
		TelegramID:       kratosx.TraitString(session.Identity.Traits, "telegram_id"),
	}
	jwtStr, _, _, err := s.signer.Sign(user.UserID, claims)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{
		"authenticated":  true,
		"user_id":        user.UserID,
		"email":          traitsEmail,
		"username":       traitsUsername,
		"aal":            session.AuthenticatorAssuranceLevel,
		"methods_used":   amr,
		"linked_methods": linked,
		"jwt":            jwtStr,
		"session_token":  sessionToken,
		"kratos": fiber.Map{
			"identity_id": session.Identity.ID,
			"session_id":  session.ID,
		},
	})
}

func (s *Server) handleSession(c *fiber.Ctx) error { return s.sessionResponse(c) }
func (s *Server) handleDebugSession(c *fiber.Ctx) error {
	session, err := s.kratos.WhoAmI(c.Context(), s.kratosToken(c))
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(session)
}
func (s *Server) handleDebugIdentity(c *fiber.Ctx) error {
	session, err := s.kratos.WhoAmI(c.Context(), s.kratosToken(c))
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "not authenticated"})
	}
	ident, err := s.kratos.GetAdminIdentity(c.Context(), session.Identity.ID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(ident)
}

func (s *Server) handleEmailOTPStart(c *fiber.Ctx) error {
	var req struct {
		Email  string `json:"email"`
		Intent string `json:"intent"`
	}
	if err := c.BodyParser(&req); err != nil || req.Email == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email required"})
	}
	kind := kratosx.FlowLogin
	if req.Intent == "register" {
		kind = kratosx.FlowRegistration
	}
	res, err := s.kratos.StartFlow(c.Context(), kind, s.kratosToken(c), nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start flow failed"})
	}
	body := map[string]any{"method": "code", "identifier": req.Email}
	username := kratosx.UsernameFromEmail(req.Email)
	if kind == kratosx.FlowRegistration {
		if username == "" {
			username = fmt.Sprintf("user-%s", uuid.NewString()[:8])
		}
		body = map[string]any{"method": "code", "traits": map[string]string{"email": req.Email, "username": username}}
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kind, res.Flow.ID, body, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	flow := sub.Flow
	if flow == nil {
		flow = res.Flow
	}
	ref, err := s.saveFlowRef(c.Context(), kind, flow, req.Email, username)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"flow_ref": ref, "state": flow.State})
}

func (s *Server) handleEmailOTPVerify(c *fiber.Ctx) error {
	var req struct {
		FlowRef string `json:"flow_ref"`
		Code    string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	rec, err := s.store.GetFlow(c.Context(), req.FlowRef)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	kind := kratosx.FlowKind(rec.Kind)
	body := map[string]any{"method": "code", "code": req.Code}
	if kind == kratosx.FlowRegistration {
		username := rec.Username
		if username == "" {
			username = kratosx.UsernameFromEmail(rec.Email)
		}
		if username == "" {
			username = fmt.Sprintf("user-%s", uuid.NewString()[:8])
		}
		body["traits"] = map[string]string{"email": rec.Email, "username": username}
	} else {
		body["identifier"] = rec.Email
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kind, rec.KratosFlowID, body, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	if sub.Status != http.StatusOK {
		return c.Status(sub.Status).JSON(fiber.Map{"error_id": sub.ErrorID, "flow": sub.Flow})
	}
	return s.sessionResponse(c)
}

func (s *Server) handlePasskeyRegisterStart(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	req.Username = strings.TrimSpace(req.Username)
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowRegistration, s.kratosToken(c), nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start flow failed"})
	}
	opts, ok := kratosx.NodeValue(res.Flow, "passkey_create_data")
	if !ok {
		return c.Status(500).JSON(fiber.Map{"error": "passkey_create_data missing"})
	}
	ref, _ := s.saveFlowRef(c.Context(), kratosx.FlowRegistration, res.Flow, "", req.Username)
	var parsed any
	_ = json.Unmarshal([]byte(opts), &parsed)
	return c.JSON(fiber.Map{"flow_ref": ref, "creation_options": parsed})
}

func (s *Server) handlePasskeyRegisterFinish(c *fiber.Ctx) error {
	var req struct {
		FlowRef    string          `json:"flow_ref"`
		Credential json.RawMessage `json:"credential"`
		Username   string          `json:"username"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	rec, err := s.store.GetFlow(c.Context(), req.FlowRef)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	body := map[string]any{"method": "passkey"}
	cred, err := passkeyCredentialPayload(req.Credential)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	body["passkey_register"] = cred
	username := passkeyTraitsUsername(req.Username, rec.Username)
	body["traits"] = map[string]string{"username": username}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowRegistration, rec.KratosFlowID, body, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	if sub.Status != http.StatusOK {
		return c.Status(sub.Status).JSON(fiber.Map{"error_id": sub.ErrorID, "flow": sub.Flow})
	}
	return s.sessionResponse(c)
}

func (s *Server) handlePasskeyLoginStart(c *fiber.Ctx) error {
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowLogin, s.kratosToken(c), nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start flow failed"})
	}
	opts, ok := kratosx.NodeValue(res.Flow, "passkey_challenge")
	if !ok {
		return c.Status(500).JSON(fiber.Map{"error": "passkey_challenge missing"})
	}
	ref, _ := s.saveFlowRef(c.Context(), kratosx.FlowLogin, res.Flow, "", "")
	var parsed any
	_ = json.Unmarshal([]byte(opts), &parsed)
	return c.JSON(fiber.Map{"flow_ref": ref, "request_options": parsed})
}

func (s *Server) handlePasskeyLoginFinish(c *fiber.Ctx) error {
	var req struct {
		FlowRef    string          `json:"flow_ref"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	rec, err := s.store.GetFlow(c.Context(), req.FlowRef)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	cred, err := passkeyCredentialPayload(req.Credential)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowLogin, rec.KratosFlowID, map[string]any{
		"method": "passkey", "passkey_login": cred,
	}, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	if sub.Status != http.StatusOK {
		return c.Status(sub.Status).JSON(fiber.Map{
			"error_id": sub.ErrorID,
			"flow":     sub.Flow,
			"messages": kratosx.FlowMessages(sub.Flow),
		})
	}
	return s.sessionResponse(c)
}

func (s *Server) handleOIDCStart(c *fiber.Ctx) error {
	provider := c.Params("provider")
	var req struct {
		Intent string `json:"intent"`
	}
	_ = c.BodyParser(&req)
	if req.Intent == "" {
		req.Intent = "login"
	}
	return s.startOIDCFlow(c, provider, req.Intent)
}

func (s *Server) handleStepUpGoogleStart(c *fiber.Ctx) error {
	return s.startOIDCFlow(c, "google", "stepup")
}

func (s *Server) startOIDCFlow(c *fiber.Ctx, provider, intent string) error {
	kind := kratosx.FlowLogin
	token := s.kratosToken(c)
	switch intent {
	case "register":
		kind = kratosx.FlowRegistration
	case "link":
		kind = kratosx.FlowSettings
	case "stepup":
		if token == "" {
			return c.Status(401).JSON(fiber.Map{
				"error": "sign in first",
				"hint":  "Link Google under Linked methods first if this account has no Google credential.",
			})
		}
		kind = kratosx.FlowLogin
	}

	query := url.Values{}
	var ctxID string
	browserStepUp := intent == "stepup"

	if kind == kratosx.FlowSettings {
		if token == "" {
			return c.Status(401).JSON(fiber.Map{"error": "login required to link provider"})
		}
	} else if browserStepUp {
		// Refresh login with an existing API session: Kratos does not issue
		// session_token_exchange_code (see login/handler.go). Use browser flow +
		// return_to redirect instead, forwarding continuity cookies like OIDC link.
		ctxID = uuid.NewString()
		query.Set("return_to", fmt.Sprintf("%s/api/v1/auth/oidc/stepup/done?ctx=%s", s.cfg.PublicBaseURL, ctxID))
		query.Set("refresh", "true")
		priorSession, err := s.kratos.WhoAmI(c.Context(), token)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "not authenticated"})
		}
		if err := s.store.SaveOIDCContext(c.Context(), store.OIDCContext{
			CtxID:             ctxID,
			Intent:            intent,
			PriorSessionToken: token,
			PriorSessionID:    priorSession.ID,
			StepUpProvider:    provider,
		}); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "save step-up context failed"})
		}
	} else {
		ctxID = uuid.NewString()
		returnTo := fmt.Sprintf("%s/api/v1/auth/oidc/return?ctx=%s", s.cfg.PublicBaseURL, ctxID)
		query.Set("return_session_token_exchange_code", "true")
		query.Set("return_to", returnTo)
	}

	logFields := logrus.Fields{
		"provider":       provider,
		"intent":         intent,
		"kind":           kind,
		"ctx_id":         ctxID,
		"flow":           "oidc_start",
		"browser_stepup": browserStepUp,
	}

	var res *kratosx.SubmitResult
	var err error
	if browserStepUp {
		res, err = s.kratos.StartBrowserFlow(c.Context(), kind, token, query)
	} else {
		res, err = s.kratos.StartFlow(c.Context(), kind, token, query)
	}
	if err != nil || res.Flow == nil {
		s.log.WithFields(logFields).WithError(err).Error("oidc start flow failed")
		return c.Status(500).JSON(fiber.Map{"error": "start flow failed", "debug": logFields})
	}
	if intent == "link" || browserStepUp {
		cookies.ApplySetCookies(c, res.SetCookies)
	}
	logFields["kratos_flow_id"] = res.Flow.ID

	if kind != kratosx.FlowSettings && !browserStepUp {
		initCode := kratosx.ExtractExchangeInitCode(res)
		logFields["init_code_present"] = initCode != ""
		if initCode == "" {
			s.log.WithFields(logFields).Error("oidc init code missing from kratos flow")
			return c.Status(500).JSON(fiber.Map{
				"error": "session token exchange code missing",
				"debug": logFields,
			})
		}
		if err := s.store.SaveOIDCContext(c.Context(), store.OIDCContext{
			CtxID: ctxID, InitCode: initCode, Intent: intent,
		}); err != nil {
			s.log.WithFields(logFields).WithError(err).Error("oidc context save failed")
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
	}

	upstream := oidcUpstreamParams(provider, intent)
	body := map[string]any{"method": "oidc", "provider": provider}
	if intent == "link" {
		body = map[string]any{"method": "oidc", "link": provider}
	}
	if browserStepUp {
		if csrf, ok := kratosx.NodeValue(res.Flow, "csrf_token"); ok {
			body["csrf_token"] = csrf
		}
	}
	if len(upstream) > 0 {
		body["upstream_parameters"] = upstream
		logFields["upstream_parameters"] = upstream
	}

	sub, err := s.kratos.SubmitFlow(c.Context(), kind, res.Flow.ID, body, token)
	if err != nil {
		s.log.WithFields(logFields).WithError(err).Error("oidc submit failed")
		return c.Status(500).JSON(fiber.Map{"error": err.Error(), "debug": logFields})
	}
	logFields["kratos_status"] = sub.Status
	logFields["error_id"] = sub.ErrorID

	if sub.RedirectBrowserTo == "" {
		sub.RedirectBrowserTo = kratosx.ExtractRedirectBrowserTo(sub)
	}
	if sub.RedirectBrowserTo == "" {
		s.log.WithFields(logFields).Error("oidc submit returned no redirect")
		return c.Status(500).JSON(fiber.Map{
			"error":    "no redirect",
			"error_id": sub.ErrorID,
			"debug":    logFields,
			"body":     json.RawMessage(sub.RawBody),
		})
	}

	redirect := sub.RedirectBrowserTo
	if strings.HasPrefix(redirect, s.cfg.KratosPublicURL) {
		redirect = strings.Replace(redirect, s.cfg.KratosPublicURL, s.cfg.PublicBaseURL+"/auth/kratos", 1)
	}
	if p := upstream["prompt"]; p != "" {
		redirect = ensureOAuthPrompt(redirect, p)
	}
	if provider == "telegram" {
		var before, after int
		var err error
		redirect, before, after, err = shortenTelegramOIDCRedirect(c.Context(), s.store, redirect)
		if err != nil {
			s.log.WithFields(logFields).WithError(err).Error("telegram state shorten failed")
			return c.Status(500).JSON(fiber.Map{"error": "telegram state mapping failed"})
		}
		logFields["telegram_state_before"] = before
		logFields["telegram_state_after"] = after
	}
	logFields["oauth_prompt"] = oauthPromptFromURL(redirect)
	logFields["redirect_host"] = hostFromURL(redirect)
	s.log.WithFields(logFields).Info("oidc redirect ready")

	if intent == "link" || browserStepUp {
		cookies.ApplySetCookies(c, sub.SetCookies)
	}
	out := fiber.Map{"redirect_url": redirect, "debug": logFields}
	if intent == "stepup" {
		out["hint"] = "Complete Google sign-in; session methods_used should include oidc:google."
	}
	return c.JSON(out)
}

// handleOIDCStepUpDone is the browser return_to target after Google OIDC step-up (refresh login).
// Kratos ProcessLogin creates a separate OIDC-only session; merge oidc into the prior API session.
func (s *Server) handleOIDCStepUpDone(c *fiber.Ctx) error {
	ctxID := c.Query("ctx")
	logFields := logrus.Fields{"flow": "oidc_stepup_done", "ctx_id": ctxID}

	token := s.kratosToken(c)
	if ctxID != "" {
		oidcCtx, err := s.store.GetOIDCContext(c.Context(), ctxID)
		if err != nil {
			s.log.WithFields(logFields).WithError(err).Warn("oidc step-up context lookup failed")
			return c.Redirect("/?oidc_error=stepup_ctx_missing")
		}
		if oidcCtx.PriorSessionToken != "" {
			token = oidcCtx.PriorSessionToken
		}
		logFields["prior_session_id"] = oidcCtx.PriorSessionID
		logFields["stepup_provider"] = oidcCtx.StepUpProvider

		if err := s.mergeOIDCStepUp(c.Context(), *oidcCtx); err != nil {
			s.log.WithFields(logFields).WithError(err).Warn("oidc step-up session merge failed")
		}
		_ = s.store.DeleteOIDCContext(c.Context(), ctxID)
	}

	logFields["token_present"] = token != ""
	if token == "" {
		s.log.WithFields(logFields).Warn("oidc step-up done without session token")
		return c.Redirect("/?oidc_error=stepup_no_session")
	}

	session, err := s.kratos.WhoAmI(c.Context(), token)
	if err != nil {
		s.log.WithFields(logFields).WithError(err).Warn("oidc step-up done whoami failed")
		return c.Redirect("/?oidc_error=stepup_whoami_failed")
	}
	logFields["methods_used"] = kratosx.MethodsUsed(session)
	s.log.WithFields(logFields).Info("oidc step-up done")
	cookies.SetSessionToken(c, s.cfg.PublicBaseURL, token)
	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.SendString(oidcReturnHTML(token, "stepup"))
}

func (s *Server) mergeOIDCStepUp(ctx context.Context, oidcCtx store.OIDCContext) error {
	if oidcCtx.PriorSessionID == "" || oidcCtx.StepUpProvider == "" {
		return fmt.Errorf("incomplete step-up context")
	}
	if s.cfg.KratosDSN == "" {
		return fmt.Errorf("KRATOS_DSN required for OIDC step-up merge")
	}

	provider := oidcCtx.StepUpProvider
	method := sessionmerge.AuthMethod{
		Method:      "oidc",
		AAL:         "aal1",
		Provider:    provider,
		CompletedAt: time.Now().UTC(),
	}

	prior, err := s.kratos.WhoAmI(ctx, oidcCtx.PriorSessionToken)
	if err != nil {
		return fmt.Errorf("prior whoami: %w", err)
	}
	if kratosx.HasAuthMethod(prior, "oidc", provider) {
		return nil
	}

	var orphanID string
	if sessions, err := s.kratos.ListIdentitySessions(ctx, prior.Identity.ID); err == nil {
		for _, sess := range sessions {
			if sess.ID == oidcCtx.PriorSessionID || !sess.Active {
				continue
			}
			if kratosx.HasAuthMethod(&kratosx.WhoAmI{AuthenticationMethods: sess.AuthenticationMethods}, "oidc", provider) {
				orphanID = sess.ID
				for _, m := range sess.AuthenticationMethods {
					if m.Method == "oidc" && m.Provider == provider {
						method.CompletedAt = m.CompletedAt
						break
					}
				}
				break
			}
		}
	}

	appended, err := sessionmerge.AppendMethod(ctx, s.cfg.KratosDSN, oidcCtx.PriorSessionID, method)
	if err != nil {
		return err
	}
	if appended && orphanID != "" {
		_ = s.kratos.RevokeSession(ctx, orphanID)
	}
	return nil
}

func (s *Server) handleOIDCReturn(c *fiber.Ctx) error {
	ctxID := c.Query("ctx")
	code := c.Query("code")
	logFields := logrus.Fields{
		"flow":         "oidc_return",
		"ctx_id":       ctxID,
		"code_present": code != "",
		"query":        c.Queries(),
	}
	if ctxID == "" || code == "" {
		s.log.WithFields(logFields).Warn("oidc return missing ctx or code")
		reason := "missing_params"
		if ctxID != "" {
			reason = "kratos_callback_failed"
		}
		return c.Redirect("/?oidc_error=" + reason + "&ctx=" + ctxID)
	}
	oidcCtx, err := s.store.GetOIDCContext(c.Context(), ctxID)
	if err != nil {
		s.log.WithFields(logFields).WithError(err).Warn("oidc context lookup failed")
		return c.Status(400).JSON(fiber.Map{"error": err.Error(), "debug": logFields})
	}
	logFields["intent"] = oidcCtx.Intent
	ex, err := s.kratos.ExchangeSessionToken(c.Context(), oidcCtx.InitCode, code)
	if err != nil {
		s.log.WithFields(logFields).WithError(err).Error("oidc token exchange failed")
		return c.Redirect("/?oidc_error=exchange_failed&ctx=" + ctxID)
	}
	logFields["session_token_len"] = len(ex.SessionToken)
	if _, err := s.kratos.WhoAmI(c.Context(), ex.SessionToken); err != nil {
		s.log.WithFields(logFields).WithError(err).Error("oidc exchanged token rejected by whoami")
		return c.Redirect("/?oidc_error=whoami_failed&ctx=" + ctxID)
	}
	logFields["whoami_ok"] = true
	s.log.WithFields(logFields).Info("oidc token exchange succeeded")
	cookies.SetSessionToken(c, s.cfg.PublicBaseURL, ex.SessionToken)
	c.Set("Content-Type", "text/html; charset=utf-8")
	oidcResult := "ok"
	if oidcCtx.Intent == "stepup" {
		oidcResult = "stepup"
	}
	return c.SendString(oidcReturnHTML(ex.SessionToken, oidcResult))
}

func (s *Server) handleMethods(c *fiber.Ctx) error {
	session, err := s.kratos.WhoAmI(c.Context(), s.kratosToken(c))
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "not authenticated"})
	}
	ident, err := s.kratos.GetAdminIdentity(c.Context(), session.Identity.ID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	methods := []fiber.Map{}
	if cred, ok := ident.Credentials["oidc"]; ok {
		var cfg struct {
			Providers []struct {
				Provider string `json:"provider"`
				Subject  string `json:"subject"`
			} `json:"providers"`
		}
		_ = json.Unmarshal(cred.Config, &cfg)
		for _, p := range cfg.Providers {
			methods = append(methods, fiber.Map{"type": "oidc", "provider": p.Provider, "label": p.Provider + ":" + p.Subject, "can_remove": true})
		}
	}
	if cred, ok := ident.Credentials["passkey"]; ok {
		var cfg struct {
			Credentials []struct {
				ID          string `json:"id"`
				DisplayName string `json:"display_name"`
			} `json:"credentials"`
		}
		_ = json.Unmarshal(cred.Config, &cfg)
		for _, pk := range cfg.Credentials {
			methods = append(methods, fiber.Map{"type": "passkey", "provider": "passkey", "label": pk.DisplayName, "credential_id": pk.ID, "can_remove": true})
		}
	}
	if cred, ok := ident.Credentials["totp"]; ok && len(cred.Config) > 0 {
		var cfg struct {
			TOTPURL string `json:"totp_url"`
		}
		_ = json.Unmarshal(cred.Config, &cfg)
		if cfg.TOTPURL != "" {
			methods = append(methods, fiber.Map{"type": "totp", "provider": "totp", "label": "TOTP", "can_remove": true})
		}
	}
	if cred, ok := ident.Credentials["code"]; ok {
		var cfg struct {
			Addresses []struct {
				Address string `json:"address"`
			} `json:"addresses"`
		}
		_ = json.Unmarshal(cred.Config, &cfg)
		for _, a := range cfg.Addresses {
			methods = append(methods, fiber.Map{"type": "email_otp", "provider": "email_otp", "label": a.Address, "can_remove": false})
		}
	}
	return c.JSON(methods)
}

func (s *Server) handlePasskeyLinkStart(c *fiber.Ctx) error {
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowSettings, s.kratosToken(c), nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start settings flow failed", "error_id": res.ErrorID})
	}
	opts, ok := kratosx.NodeValue(res.Flow, "passkey_create_data")
	if !ok {
		return c.Status(403).JSON(fiber.Map{"error_id": res.ErrorID, "hint": "session_refresh_required?"})
	}
	ref, _ := s.saveFlowRef(c.Context(), kratosx.FlowSettings, res.Flow, "", "")
	var parsed any
	_ = json.Unmarshal([]byte(opts), &parsed)
	return c.JSON(fiber.Map{"flow_ref": ref, "creation_options": parsed})
}

func (s *Server) handlePasskeyLinkFinish(c *fiber.Ctx) error {
	var req struct {
		FlowRef    string          `json:"flow_ref"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	rec, err := s.store.GetFlow(c.Context(), req.FlowRef)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	cred, err := passkeyCredentialPayload(req.Credential)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowSettings, rec.KratosFlowID, map[string]any{
		"method": "passkey", "passkey_settings_register": cred,
	}, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if sub.ErrorID == "session_refresh_required" {
		return c.Status(403).JSON(fiber.Map{"error_id": sub.ErrorID})
	}
	s.persistSessionToken(c, sub)
	return s.sessionResponse(c)
}

func (s *Server) handlePasskeyRemove(c *fiber.Ctx) error {
	id := c.Params("id")
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowSettings, s.kratosToken(c), nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start settings flow failed"})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowSettings, res.Flow.ID, map[string]any{
		"method": "passkey", "passkey_remove": id,
	}, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	return s.sessionResponse(c)
}

func (s *Server) handleEmailOTPLinkStart(c *fiber.Ctx) error {
	token := s.kratosToken(c)
	if token == "" {
		return c.Status(401).JSON(fiber.Map{"error": "sign in first"})
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Email) == "" {
		return c.Status(400).JSON(fiber.Map{"error": "email required"})
	}
	req.Email = strings.TrimSpace(req.Email)

	session, err := s.kratos.WhoAmI(c.Context(), token)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "not authenticated"})
	}
	admin, _ := s.kratos.GetAdminIdentity(c.Context(), session.Identity.ID)
	if kratosx.HasLinkedMethod(admin, "email_otp") {
		return c.Status(409).JSON(fiber.Map{
			"error": "email OTP already linked",
			"hint":  "This identity already has an email OTP address.",
		})
	}

	// Settings profile update is identity-aware and triggers courier to the NEW address.
	// Standalone verification flow treats the address as "unknown" and sends no OTP (was_notified=false).
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowSettings, token, nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start settings flow failed", "error_id": res.ErrorID})
	}
	if res.ErrorID == "session_refresh_required" {
		return c.Status(403).JSON(fiber.Map{
			"error_id": res.ErrorID,
			"hint":     "Click Re-auth (refresh) under Step-up, then retry Link email OTP.",
		})
	}

	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowSettings, res.Flow.ID, map[string]any{
		"method": "profile",
		"traits": profileTraitsForUpdate(session.Identity.Traits, req.Email),
	}, token)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if verFlowID, _, ok := kratosx.ContinueWithVerification(sub); ok {
		ref, err := s.saveFlowRef(c.Context(), kratosx.FlowVerification, &kratosx.FlowResponse{ID: verFlowID}, req.Email, kratosx.TraitString(session.Identity.Traits, "username"))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{
			"flow_ref":           ref,
			"needs_verification": true,
			"email":              req.Email,
			"messages":           kratosx.FlowMessages(sub.Flow),
			"hint":               "OTP sent via settings profile update — check Last OTP or auth-service log otp_code=…",
		})
	}

	flow := sub.Flow
	if flow == nil {
		flow = res.Flow
	}
	if kratosx.FlowAwaitingCode(flow) {
		ref, err := s.saveFlowRef(c.Context(), kratosx.FlowSettings, flow, req.Email, kratosx.TraitString(session.Identity.Traits, "username"))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{
			"flow_ref":           ref,
			"needs_verification": true,
			"email":              req.Email,
			"messages":           kratosx.FlowMessages(flow),
			"hint":               "Enter the verification code below.",
		})
	}

	if sub.Status == http.StatusOK {
		s.persistSessionToken(c, sub)
		return s.sessionResponse(c)
	}

	return c.Status(sub.Status).JSON(fiber.Map{
		"error_id": sub.ErrorID,
		"flow":     sub.Flow,
		"messages": kratosx.FlowMessages(sub.Flow),
		"hint":     "Profile update did not enter verification — try Re-auth (refresh) and retry.",
	})
}

func (s *Server) handleEmailOTPLinkVerify(c *fiber.Ctx) error {
	token := s.kratosToken(c)
	if token == "" {
		return c.Status(401).JSON(fiber.Map{"error": "sign in first"})
	}
	var req struct {
		FlowRef string `json:"flow_ref"`
		Code    string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "flow_ref and code required"})
	}
	rec, err := s.store.GetFlow(c.Context(), req.FlowRef)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	kind := kratosx.FlowKind(rec.Kind)
	body := map[string]any{"method": "code", "code": req.Code}
	switch kind {
	case kratosx.FlowSettings:
		body["traits"] = profileTraitsForUpdate(map[string]any{
			"username": rec.Username,
		}, rec.Email)
	case kratosx.FlowVerification:
		if rec.Email != "" {
			body["email"] = rec.Email
		}
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kind, rec.KratosFlowID, body, token)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if sub.Status != http.StatusOK {
		return c.Status(sub.Status).JSON(fiber.Map{
			"error_id": sub.ErrorID,
			"flow":     sub.Flow,
			"messages": kratosx.FlowMessages(sub.Flow),
		})
	}

	s.persistSessionToken(c, sub)
	return s.sessionResponse(c)
}

func (s *Server) handleOIDCUnlink(c *fiber.Ctx) error {
	provider := c.Params("provider")
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowSettings, s.kratosToken(c), nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start settings flow failed"})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowSettings, res.Flow.ID, map[string]any{
		"method": "oidc", "unlink": provider,
	}, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	return s.sessionResponse(c)
}

func (s *Server) handleTOTPStart(c *fiber.Ctx) error {
	token := s.kratosToken(c)
	if token == "" {
		return c.Status(401).JSON(fiber.Map{"error": "sign in first"})
	}
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowSettings, token, nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start settings flow failed", "error_id": res.ErrorID})
	}
	if res.ErrorID == "session_refresh_required" {
		return c.Status(403).JSON(fiber.Map{
			"error_id": res.ErrorID,
			"hint":     "Click “Re-auth (refresh)” under Step-up, complete login, then retry Enroll TOTP.",
		})
	}
	if kratosx.NodeByName(res.Flow, "totp_unlink") != nil {
		return c.Status(409).JSON(fiber.Map{"error": "TOTP already enrolled — use Remove TOTP first to re-enroll"})
	}
	node := kratosx.NodeByName(res.Flow, "totp_secret_key")
	secret := kratosx.TOTPSecret(node)
	if secret == "" {
		return c.Status(403).JSON(fiber.Map{
			"error_id": res.ErrorID,
			"hint":     "TOTP setup unavailable — sign in and try Re-auth (refresh) if the session is older than 1h.",
		})
	}
	qr := ""
	if n := kratosx.NodeByName(res.Flow, "totp_qr"); n != nil {
		qr = n.Attributes.Src
	}
	ref, _ := s.saveFlowRef(c.Context(), kratosx.FlowSettings, res.Flow, "", "")
	return c.JSON(fiber.Map{"flow_ref": ref, "secret": secret, "qr_data_uri": qr})
}

func (s *Server) handleTOTPConfirm(c *fiber.Ctx) error {
	var req struct {
		FlowRef string `json:"flow_ref"`
		Code    string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	rec, err := s.store.GetFlow(c.Context(), req.FlowRef)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowSettings, rec.KratosFlowID, map[string]any{
		"method": "totp", "totp_code": req.Code,
	}, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	return s.sessionResponse(c)
}

func (s *Server) handleTOTPDelete(c *fiber.Ctx) error {
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowSettings, s.kratosToken(c), nil)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start settings flow failed"})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowSettings, res.Flow.ID, map[string]any{
		"method": "totp", "totp_unlink": true,
	}, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	return s.sessionResponse(c)
}

func (s *Server) handleStepUpAAL2Start(c *fiber.Ctx) error {
	q := url.Values{"aal": []string{"aal2"}}
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowLogin, s.kratosToken(c), q)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start step-up flow failed"})
	}
	ref, _ := s.saveFlowRef(c.Context(), kratosx.FlowLogin, res.Flow, "", "")
	return c.JSON(fiber.Map{"flow_ref": ref, "available": []string{"totp"}})
}

func (s *Server) handleStepUpAAL2TOTP(c *fiber.Ctx) error {
	var req struct {
		FlowRef string `json:"flow_ref"`
		Code    string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
	}
	rec, err := s.store.GetFlow(c.Context(), req.FlowRef)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowLogin, rec.KratosFlowID, map[string]any{
		"method": "totp", "totp_code": req.Code,
	}, s.kratosToken(c))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	return s.sessionResponse(c)
}

func (s *Server) handleStepUpRefreshStart(c *fiber.Ctx) error {
	q := url.Values{"refresh": []string{"true"}}
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowLogin, s.kratosToken(c), q)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start refresh flow failed"})
	}
	ref, _ := s.saveFlowRef(c.Context(), kratosx.FlowLogin, res.Flow, "", "")
	return c.JSON(fiber.Map{"flow_ref": ref, "message": "complete any 1FA using login endpoints"})
}

// handleStepUpPasskeyStart re-authenticates the current session with passkey (refresh login flow).
// Use after an OIDC login so authentication_methods accumulates both oidc:google and passkey.
func (s *Server) handleStepUpPasskeyStart(c *fiber.Ctx) error {
	if s.kratosToken(c) == "" {
		return c.Status(401).JSON(fiber.Map{"error": "sign in first (e.g. Google)"})
	}
	q := url.Values{"refresh": []string{"true"}}
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowLogin, s.kratosToken(c), q)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start passkey step-up failed", "error_id": res.ErrorID})
	}
	opts, ok := kratosx.NodeValue(res.Flow, "passkey_challenge")
	if !ok {
		return c.Status(500).JSON(fiber.Map{"error": "passkey_challenge missing — add a passkey under Linked methods first"})
	}
	ref, _ := s.saveFlowRef(c.Context(), kratosx.FlowLogin, res.Flow, "", "")
	var parsed any
	_ = json.Unmarshal([]byte(opts), &parsed)
	return c.JSON(fiber.Map{
		"flow_ref":        ref,
		"request_options": parsed,
		"hint":            "Complete Touch ID, then call /api/v1/policy/demo-sensitive to verify amr includes oidc:google and passkey.",
	})
}

// handleStepUpEmailOTPStart re-authenticates the current session with email OTP (refresh login flow).
func (s *Server) handleStepUpEmailOTPStart(c *fiber.Ctx) error {
	token := s.kratosToken(c)
	if token == "" {
		return c.Status(401).JSON(fiber.Map{"error": "sign in first"})
	}
	var req struct {
		Email string `json:"email"`
	}
	_ = c.BodyParser(&req)

	session, err := s.kratos.WhoAmI(c.Context(), token)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "not authenticated"})
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		email = kratosx.LinkedEmailAddress(session.Identity.Traits, nil)
	}
	if email == "" {
		admin, _ := s.kratos.GetAdminIdentity(c.Context(), session.Identity.ID)
		email = kratosx.LinkedEmailAddress(session.Identity.Traits, admin)
	}
	if email == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "no linked email OTP address",
			"hint":  "Link email OTP under Linked methods first, or pass {\"email\":\"you@example.com\"}.",
		})
	}

	q := url.Values{"refresh": []string{"true"}}
	res, err := s.kratos.StartFlow(c.Context(), kratosx.FlowLogin, token, q)
	if err != nil || res.Flow == nil {
		return c.Status(500).JSON(fiber.Map{"error": "start email OTP step-up failed", "error_id": res.ErrorID})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowLogin, res.Flow.ID, map[string]any{
		"method": "code", "identifier": email,
	}, token)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	flow := sub.Flow
	if flow == nil {
		flow = res.Flow
	}
	ref, err := s.saveFlowRef(c.Context(), kratosx.FlowLogin, flow, email, "")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{
		"flow_ref": ref,
		"email":    email,
		"state":    flow.State,
		"needs_code": true,
		"hint":     "OTP is login_code — check Step-up Last OTP below or docker logs otp_code=…",
	})
}

func (s *Server) handleStepUpEmailOTPVerify(c *fiber.Ctx) error {
	token := s.kratosToken(c)
	if token == "" {
		return c.Status(401).JSON(fiber.Map{"error": "sign in first"})
	}
	var req struct {
		FlowRef string `json:"flow_ref"`
		Code    string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Code == "" {
		return c.Status(400).JSON(fiber.Map{"error": "flow_ref and code required"})
	}
	rec, err := s.store.GetFlow(c.Context(), req.FlowRef)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}
	if kratosx.FlowKind(rec.Kind) != kratosx.FlowLogin {
		return c.Status(400).JSON(fiber.Map{"error": "invalid flow_ref for email step-up"})
	}
	sub, err := s.kratos.SubmitFlow(c.Context(), kratosx.FlowLogin, rec.KratosFlowID, map[string]any{
		"method": "code", "code": req.Code, "identifier": rec.Email,
	}, token)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	s.persistSessionToken(c, sub)
	if sub.Status != http.StatusOK {
		return c.Status(sub.Status).JSON(fiber.Map{
			"error_id": sub.ErrorID,
			"flow":     sub.Flow,
			"messages": kratosx.FlowMessages(sub.Flow),
		})
	}
	return s.sessionResponse(c)
}

// handlePolicyDemoSensitive example policy: both Google OIDC and passkey must appear in this session's AMR.
func (s *Server) handlePolicyDemoSensitive(c *fiber.Ctx) error {
	session, err := s.kratos.WhoAmI(c.Context(), s.kratosToken(c))
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "not authenticated"})
	}
	used := kratosx.MethodsUsed(session)
	required := []string{"oidc:google", "passkey"}
	if !kratosx.HasMethods(used, required) {
		return c.Status(403).JSON(fiber.Map{
			"error":    "policy_denied",
			"required": required,
			"methods_used": used,
			"aal":      session.AuthenticatorAssuranceLevel,
			"hint":     "Need both oidc:google and passkey in methods_used: Login Google → Step up passkey, or passkey login → Step up Google. Note: both stay aal1; use TOTP step-up for aal2.",
		})
	}
	return c.JSON(fiber.Map{
		"ok":           true,
		"methods_used": used,
		"aal":          session.AuthenticatorAssuranceLevel,
		"message":      "policy satisfied: session proves Google OIDC and passkey in this session",
	})
}

func (s *Server) handleLogout(c *fiber.Ctx) error {
	token := s.kratosToken(c)
	if token != "" {
		if session, err := s.kratos.WhoAmI(c.Context(), token); err == nil {
			_ = s.kratos.DisableSession(c.Context(), session.ID)
		}
	}
	cookies.ClearSessionToken(c, s.cfg.PublicBaseURL)
	return c.JSON(fiber.Map{"ok": true})
}

func (s *Server) handleDeleteAccount(c *fiber.Ctx) error {
	session, err := s.kratos.WhoAmI(c.Context(), s.kratosToken(c))
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "not authenticated"})
	}
	user, _ := s.store.GetUserByKratosID(c.Context(), session.Identity.ID)
	if err := s.kratos.DeleteIdentity(c.Context(), session.Identity.ID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if user != nil {
		_ = s.store.DeleteUserData(c.Context(), user.UserID, session.Identity.ID)
	}
	cookies.ClearSessionToken(c, s.cfg.PublicBaseURL)
	return c.JSON(fiber.Map{"ok": true})
}

func (s *Server) proxyKratos(c *fiber.Ctx) error {
	target := strings.TrimPrefix(c.Path(), "/auth/kratos")
	if target == "" {
		target = "/"
	}
	u := s.cfg.KratosPublicURL + target
	if q := c.Context().QueryArgs().String(); q != "" {
		u += "?" + q
	}
	if strings.Contains(target, "/oidc/callback/telegram") {
		if expanded, ok, err := expandTelegramCallbackURL(c.Context(), s.store, u); err == nil && ok {
			s.log.WithFields(logrus.Fields{
				"flow":            "telegram_state_expand",
				"short_state_len": len(c.Query("state")),
			}).Info("restored kratos oidc state for telegram callback")
			u = expanded
		}
	}
	if strings.Contains(target, "/oidc/callback/") {
		s.log.WithFields(logrus.Fields{
			"flow":              "oidc_callback_proxy",
			"path":              target,
			"method":            c.Method(),
			"query":             c.Queries(),
			"has_session_token": s.kratosToken(c) != "",
		}).Info("proxying kratos oidc callback")
	}
	return s.reverseProxy(c, u)
}

func (s *Server) reverseProxy(c *fiber.Ctx, targetURL string) error {
	req, err := http.NewRequestWithContext(c.Context(), c.Method(), targetURL, bytesReader(c))
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}
	if token := s.kratosToken(c); token != "" {
		req.Header.Set("X-Session-Token", token)
	}
	if browserCookie := c.Get("Cookie"); browserCookie != "" {
		req.Header.Set("Cookie", browserCookie)
	}
	for k, v := range c.GetReqHeaders() {
		if len(v) > 0 && strings.EqualFold(k, "Content-Type") {
			req.Header.Set(k, v[0])
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return c.Status(502).SendString(err.Error())
	}
	defer resp.Body.Close()
	c.Status(resp.StatusCode)
	for k, vals := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vals {
			if strings.EqualFold(k, "Location") {
				v = strings.Replace(v, s.cfg.KratosPublicURL, s.cfg.PublicBaseURL+"/auth/kratos", 1)
				if strings.Contains(v, s.cfg.PublicBaseURL+"/?") || strings.HasSuffix(v, s.cfg.PublicBaseURL+"/") {
					// link flow landed on default return — send user home
					v = s.cfg.PublicBaseURL + "/?oidc=linked"
				}
			}
			c.Set(k, v)
		}
	}
	cookies.ApplySetCookies(c, resp.Cookies())
	body, _ := io.ReadAll(resp.Body)
	return c.Send(body)
}

func oidcSubject(ident *kratosx.AdminIdentity, provider string) string {
	if ident == nil {
		return ""
	}
	cred, ok := ident.Credentials["oidc"]
	if !ok {
		return ""
	}
	var cfg struct {
		Providers []struct {
			Provider string `json:"provider"`
			Subject  string `json:"subject"`
		} `json:"providers"`
	}
	if json.Unmarshal(cred.Config, &cfg) != nil {
		return ""
	}
	for _, p := range cfg.Providers {
		if p.Provider == provider {
			return p.Subject
		}
	}
	return ""
}

func bytesReader(c *fiber.Ctx) io.Reader {
	if len(c.Body()) == 0 {
		return nil
	}
	return strings.NewReader(string(c.Body()))
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

func otpFromPayload(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	for _, key := range []string{"verification_code", "login_code", "registration_code", "recovery_code"} {
		if v, ok := payload[key].(string); ok && v != "" {
			return v
		}
	}
	if td, ok := payload["template_data"].(map[string]any); ok {
		for _, key := range []string{"verification_code", "login_code", "registration_code", "recovery_code"} {
			if v, ok := td[key].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

func otpCodeType(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	for _, key := range []string{"verification_code", "login_code", "registration_code", "recovery_code"} {
		if v, ok := payload[key].(string); ok && v != "" {
			return key
		}
	}
	if td, ok := payload["template_data"].(map[string]any); ok {
		for _, key := range []string{"verification_code", "login_code", "registration_code", "recovery_code"} {
			if v, ok := td[key].(string); ok && v != "" {
				return key
			}
		}
	}
	return ""
}

// profileTraitsForUpdate builds a valid traits payload for settings profile (schema requires username).
func profileTraitsForUpdate(existing map[string]any, email string) map[string]string {
	traits := map[string]string{}
	if u := kratosx.TraitString(existing, "username"); u != "" {
		traits["username"] = u
	}
	if email != "" {
		traits["email"] = email
	}
	return traits
}

// passkeyTraitsUsername returns the identity username trait for passkey registration.
func passkeyTraitsUsername(requested, stored string) string {
	if u := strings.TrimSpace(requested); u != "" {
		return u
	}
	if u := strings.TrimSpace(stored); u != "" {
		return u
	}
	return fmt.Sprintf("user-%s", uuid.NewString()[:8])
}

// passkeyCredentialPayload returns the raw WebAuthn JSON string Kratos expects.
func passkeyCredentialPayload(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("empty credential")
	}
	trimmed := bytes.TrimSpace(raw)
	switch trimmed[0] {
	case '{':
		return string(trimmed), nil
	case '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return "", fmt.Errorf("credential string: %w", err)
		}
		return s, nil
	default:
		return "", fmt.Errorf("credential: unexpected JSON")
	}
}

func oidcReturnHTML(sessionToken, result string) string {
	if result == "" {
		result = "ok"
	}
	// HTML bridge: persists token for the test console (sessionStorage + cookie)
	// then redirects home. Avoids ngrok/proxy cookie issues in the PoC UI.
	tokenJSON, _ := json.Marshal(sessionToken)
	resultJSON, _ := json.Marshal(result)
	return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Signing in…</title></head>
<body><p>Signing you in…</p><script>
try {
  sessionStorage.setItem('poc_kratos_session', ` + string(tokenJSON) + `);
} catch (e) {}
location.replace('/?oidc=' + ` + string(resultJSON) + `);
</script></body></html>`
}
