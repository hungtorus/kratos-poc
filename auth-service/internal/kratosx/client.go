package kratosx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	publicURL string
	adminURL  string
	http      *http.Client
}

type FlowKind string

const (
	FlowLogin        FlowKind = "login"
	FlowRegistration FlowKind = "registration"
	FlowSettings     FlowKind = "settings"
)

type FlowResponse struct {
	ID                         string          `json:"id"`
	UI                         UIModel         `json:"ui"`
	State                      string          `json:"state"`
	SessionTokenExchangeCode   string          `json:"session_token_exchange_code"`
	Identity                   json.RawMessage `json:"identity,omitempty"`
	Session                    json.RawMessage `json:"session,omitempty"`
}

type UIModel struct {
	Action   string      `json:"action"`
	Messages []UIMessage `json:"messages"`
	Nodes    []UINode    `json:"nodes"`
}

type UIMessage struct {
	ID      int64  `json:"id"`
	Text    string `json:"text"`
	Type    string `json:"type"`
	Context any    `json:"context"`
}

type UINode struct {
	Type       string         `json:"type"`
	Group      string         `json:"group"`
	Attributes UINodeAttr     `json:"attributes"`
	Meta       map[string]any `json:"meta"`
}

type UINodeAttr struct {
	Name           string         `json:"name"`
	ID             string         `json:"id"`
	Type           string         `json:"type"`
	Value          any            `json:"value"`
	Disabled       bool           `json:"disabled"`
	NodeType       string         `json:"node_type"`
	Text           *UIText        `json:"text,omitempty"`
	Src            string         `json:"src,omitempty"`
	OnClick        string         `json:"onclick,omitempty"`
	OnClickTrigger string         `json:"onclickTrigger,omitempty"`
}

type UIText struct {
	Text    string         `json:"text"`
	Context map[string]any `json:"context"`
}

type SubmitResult struct {
	Status            int
	Flow              *FlowResponse
	Session           json.RawMessage
	SessionToken      string
	RedirectBrowserTo string
	ErrorID           string
	RawBody           json.RawMessage
}

type WhoAmI struct {
	ID                          string                 `json:"id"`
	Active                      bool                   `json:"active"`
	AuthenticatorAssuranceLevel string                 `json:"authenticator_assurance_level"`
	AuthenticationMethods       []AuthenticationMethod `json:"authentication_methods"`
	Identity                    Identity               `json:"identity"`
}

type AuthenticationMethod struct {
	Method      string    `json:"method"`
	AAL         string    `json:"aal"`
	CompletedAt time.Time `json:"completed_at"`
	Provider    string    `json:"provider,omitempty"`
}

type Identity struct {
	ID     string         `json:"id"`
	Traits map[string]any `json:"traits"`
}

type AdminIdentity struct {
	ID          string                     `json:"id"`
	Traits      map[string]any             `json:"traits"`
	Credentials map[string]AdminCredential `json:"credentials"`
}

type AdminCredential struct {
	Type        string          `json:"type"`
	Identifiers []string        `json:"identifiers"`
	Config      json.RawMessage `json:"config"`
}

type TokenExchangeResult struct {
	SessionToken string          `json:"session_token"`
	Session      json.RawMessage `json:"session"`
}

func New(publicURL, adminURL string) *Client {
	return &Client{
		publicURL: strings.TrimRight(publicURL, "/"),
		adminURL:  strings.TrimRight(adminURL, "/"),
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) StartFlow(ctx context.Context, kind FlowKind, sessionToken string, query url.Values) (*SubmitResult, error) {
	if query == nil {
		query = url.Values{}
	}
	path := fmt.Sprintf("%s/self-service/%s/api?%s", c.publicURL, kind, query.Encode())
	return c.do(ctx, http.MethodGet, path, nil, sessionToken)
}

func (c *Client) SubmitFlow(ctx context.Context, kind FlowKind, flowID string, body any, sessionToken string) (*SubmitResult, error) {
	path := fmt.Sprintf("%s/self-service/%s?flow=%s", c.publicURL, kind, url.QueryEscape(flowID))
	return c.do(ctx, http.MethodPost, path, body, sessionToken)
}

func (c *Client) WhoAmI(ctx context.Context, sessionToken string) (*WhoAmI, error) {
	if sessionToken == "" {
		return nil, fmt.Errorf("whoami: empty session token")
	}
	res, err := c.do(ctx, http.MethodGet, c.publicURL+"/sessions/whoami", nil, sessionToken)
	if err != nil {
		return nil, err
	}
	if res.Status != http.StatusOK {
		return nil, fmt.Errorf("whoami: status %d error=%s", res.Status, res.ErrorID)
	}
	var s WhoAmI
	if err := json.Unmarshal(res.RawBody, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) ExchangeSessionToken(ctx context.Context, initCode, returnToCode string) (*TokenExchangeResult, error) {
	q := url.Values{
		"init_code":       {initCode},
		"return_to_code": {returnToCode},
	}
	res, err := c.do(ctx, http.MethodGet, c.publicURL+"/sessions/token-exchange?"+q.Encode(), nil, "")
	if err != nil {
		return nil, err
	}
	if res.Status != http.StatusOK {
		return nil, fmt.Errorf("token exchange: status %d body=%s", res.Status, string(res.RawBody))
	}
	var out TokenExchangeResult
	if err := json.Unmarshal(res.RawBody, &out); err != nil {
		return nil, err
	}
	if out.SessionToken == "" {
		out.SessionToken = res.SessionToken
	}
	if out.SessionToken == "" {
		return nil, fmt.Errorf("token exchange: empty session_token body=%s", string(res.RawBody))
	}
	return &out, nil
}

func (c *Client) DisableSession(ctx context.Context, sessionID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.adminURL+"/admin/sessions/"+sessionID, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("disable session: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) GetAdminIdentity(ctx context.Context, id string) (*AdminIdentity, error) {
	q := url.Values{}
	for _, t := range []string{"oidc", "passkey", "totp", "code"} {
		q.Add("include_credential", t)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.adminURL+"/admin/identities/"+id+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin identity: %d %s", resp.StatusCode, string(body))
	}
	var ident AdminIdentity
	if err := json.Unmarshal(body, &ident); err != nil {
		return nil, err
	}
	return &ident, nil
}

func (c *Client) DeleteIdentity(ctx context.Context, id string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, c.adminURL+"/admin/identities/"+id, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete identity: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, urlStr string, body any, sessionToken string) (*SubmitResult, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sessionToken != "" {
		req.Header.Set("X-Session-Token", sessionToken)
		req.Header.Set("Authorization", "Bearer "+sessionToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	result := &SubmitResult{Status: resp.StatusCode, RawBody: raw}

	var envelope struct {
		RedirectBrowserTo          string          `json:"redirect_browser_to"`
		Session                    json.RawMessage `json:"session"`
		SessionToken               string          `json:"session_token"`
		SessionTokenExchangeCode   string          `json:"session_token_exchange_code"`
		Error                      *struct {
			ID string `json:"id"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &envelope)
	result.RedirectBrowserTo = envelope.RedirectBrowserTo
	result.Session = envelope.Session
	result.SessionToken = envelope.SessionToken
	if envelope.Error != nil {
		result.ErrorID = envelope.Error.ID
	}

	var flow FlowResponse
	if json.Unmarshal(raw, &flow) == nil && flow.ID != "" {
		result.Flow = &flow
		if flow.SessionTokenExchangeCode != "" && result.SessionToken == "" {
			// init code lives on flow for native OIDC flows
			_ = flow.SessionTokenExchangeCode
		}
	}
	if envelope.SessionTokenExchangeCode != "" && result.Flow != nil {
		result.Flow.SessionTokenExchangeCode = envelope.SessionTokenExchangeCode
	}
	return result, nil
}

func NodeValue(flow *FlowResponse, name string) (string, bool) {
	if flow == nil {
		return "", false
	}
	for _, n := range flow.UI.Nodes {
		if n.Attributes.Name == name {
			switch v := n.Attributes.Value.(type) {
			case string:
				return v, true
			default:
				b, _ := json.Marshal(v)
				return string(b), true
			}
		}
	}
	return "", false
}

func FlowMessages(flow *FlowResponse) []string {
	if flow == nil {
		return nil
	}
	out := make([]string, 0, len(flow.UI.Messages))
	for _, m := range flow.UI.Messages {
		if m.Text != "" {
			out = append(out, m.Text)
		}
	}
	return out
}

func NodeByName(flow *FlowResponse, name string) *UINode {
	if flow == nil {
		return nil
	}
	for i := range flow.UI.Nodes {
		n := &flow.UI.Nodes[i]
		if n.Attributes.Name == name || n.Attributes.ID == name {
			return n
		}
	}
	return nil
}

func TOTPSecret(node *UINode) string {
	if node == nil || node.Attributes.Text == nil {
		return ""
	}
	if s, ok := node.Attributes.Text.Context["secret"].(string); ok && s != "" {
		return s
	}
	return node.Attributes.Text.Text
}

func AggregateLinkedMethods(ident *AdminIdentity) []string {
	if ident == nil {
		return nil
	}
	seen := map[string]struct{}{}
	add := func(s string) {
		if s == "" {
			return
		}
		seen[s] = struct{}{}
	}
	if c, ok := ident.Credentials["oidc"]; ok && len(c.Config) > 0 {
		var cfg struct {
			Providers []struct {
				Provider string `json:"provider"`
			} `json:"providers"`
		}
		if json.Unmarshal(c.Config, &cfg) == nil {
			for _, p := range cfg.Providers {
				add(p.Provider)
			}
		}
	}
	if c, ok := ident.Credentials["passkey"]; ok && len(c.Config) > 0 {
		var cfg struct {
			Credentials []any `json:"credentials"`
		}
		if json.Unmarshal(c.Config, &cfg) == nil && len(cfg.Credentials) > 0 {
			add("passkey")
		}
	}
	if c, ok := ident.Credentials["totp"]; ok && len(c.Config) > 0 {
		var cfg struct {
			TOTPURL string `json:"totp_url"`
		}
		if json.Unmarshal(c.Config, &cfg) == nil && cfg.TOTPURL != "" {
			add("totp")
		}
	}
	if c, ok := ident.Credentials["code"]; ok && len(c.Config) > 0 {
		var cfg struct {
			Addresses []any `json:"addresses"`
		}
		if json.Unmarshal(c.Config, &cfg) == nil && len(cfg.Addresses) > 0 {
			add("email_otp")
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func MethodsUsed(session *WhoAmI) []string {
	if session == nil {
		return nil
	}
	out := make([]string, 0, len(session.AuthenticationMethods))
	for _, m := range session.AuthenticationMethods {
		if m.Provider != "" {
			out = append(out, fmt.Sprintf("%s:%s", m.Method, m.Provider))
		} else {
			out = append(out, m.Method)
		}
	}
	return out
}

// HasMethods reports whether every required AMR entry appears in used (exact match).
func HasMethods(used, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(used))
	for _, m := range used {
		set[m] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}

func TraitString(traits map[string]any, key string) string {
	if traits == nil {
		return ""
	}
	v, ok := traits[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func ExtractSessionToken(res *SubmitResult) string {
	if res == nil {
		return ""
	}
	if res.SessionToken != "" {
		return res.SessionToken
	}
	var top struct {
		SessionToken string `json:"session_token"`
	}
	if json.Unmarshal(res.RawBody, &top) == nil && top.SessionToken != "" {
		return top.SessionToken
	}
	return ""
}

func ExtractExchangeInitCode(res *SubmitResult) string {
	if res == nil {
		return ""
	}
	if res.Flow != nil && res.Flow.SessionTokenExchangeCode != "" {
		return res.Flow.SessionTokenExchangeCode
	}
	var top struct {
		SessionTokenExchangeCode string `json:"session_token_exchange_code"`
	}
	if json.Unmarshal(res.RawBody, &top) == nil && top.SessionTokenExchangeCode != "" {
		return top.SessionTokenExchangeCode
	}
	return ""
}
