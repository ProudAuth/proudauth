package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/egress"
)

// External policy engines (AZ-026): a realm may delegate decisions to an
// engine the operator configured. The engine receives the same tenant,
// subject, actor and token context local evaluation uses, plus the local
// answer, over an authenticated call with a hard timeout; what an
// unreachable or malformed engine means is the realm's explicit choice
// (deny by default).

type engineInput struct {
	Realm          string         `json:"realm"`
	OrganizationID string         `json:"organization_id,omitempty"`
	Subject        map[string]any `json:"subject"`
	Actor          string         `json:"actor,omitempty"`
	ClientID       string         `json:"client_id,omitempty"`
	Audience       string         `json:"audience,omitempty"`
	TokenKind      string         `json:"token_kind,omitempty"`
	ACR            string         `json:"acr,omitempty"`
	AuthTime       int64          `json:"auth_time,omitempty"`
	SupportMode    string         `json:"support_mode,omitempty"`
	Action         string         `json:"action"`
	Resource       map[string]any `json:"resource"`
	Context        map[string]any `json:"context,omitempty"`
	Local          map[string]any `json:"local"`
	Time           int64          `json:"time"`
}

type engineVerdict struct {
	Allowed       bool
	ReasonCode    string
	Obligations   []map[string]any
	PolicyVersion string
}

var errEngineAnswer = errors.New("policy engine: malformed answer")

// consultEngine asks the realm's engine, if any. It returns nil without an
// engine; an error means the engine could not answer.
func (a *App) consultEngine(ctx context.Context, p *Principal, req DecisionRequest, sc *subjectContext, orgID string, localAllowed bool, localReason string) (*engineVerdict, *configuration.PolicyEngineConfig, error) {
	name := p.Realm.Policy.PolicyEngine.Name
	if name == "" {
		return nil, nil, nil
	}
	cfg, ok := a.D.Cfg.PolicyEngine(name)
	if !ok {
		return nil, nil, fmt.Errorf("policy engine %q is not configured", name)
	}
	in := engineInput{Realm: p.Realm.Name, OrganizationID: orgID, Subject: map[string]any{"type": sc.subject.Type, "id": sc.subject.ID},
		Actor: sc.actor, ClientID: sc.clientID, Audience: sc.audience, TokenKind: sc.kind, ACR: sc.acr, SupportMode: sc.supportMode, Action: req.Action,
		Resource: map[string]any{"type": req.Resource.Type, "id": req.Resource.ID, "org_id": orgID}, Context: req.Context,
		Local: map[string]any{"allowed": localAllowed, "reason_code": localReason}, Time: a.D.Now().Unix()}
	if !sc.authTime.IsZero() {
		in.AuthTime = sc.authTime.Unix()
	}
	if req.Resource.ProjectID != "" {
		in.Resource["project_id"] = req.Resource.ProjectID // validated by decideWith (AZ-002)
	}
	body, _ := json.Marshal(map[string]any{"input": in})
	token, err := configuration.ResolveSecret(cfg.Token)
	if err != nil {
		return nil, cfg, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(cctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, cfg, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+token)
	// The engine is an operator-configured internal service: private
	// addresses are expected, the residency policy still applies.
	pol := egress.Policy{AllowPrivate: true, RequireHTTPS: a.D.Cfg.Mode == configuration.ModeProduction, Timeout: timeout, MaxBytes: 64 << 10}
	res, err := pol.Client().Do(hr)
	if err != nil {
		return nil, cfg, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, cfg, fmt.Errorf("policy engine: status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, cfg, errEngineAnswer
	}
	v, err := parseEngineAnswer(raw)
	return v, cfg, err
}

// parseEngineAnswer accepts {"allowed": bool, ...} or the OPA data API's
// {"result": bool} / {"result": {"allowed": bool, ...}}. Anything else is
// malformed, never an allow.
func parseEngineAnswer(raw []byte) (*engineVerdict, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, errEngineAnswer
	}
	if r, ok := top["result"]; ok {
		var b bool
		if json.Unmarshal(r, &b) == nil {
			return &engineVerdict{Allowed: b}, nil
		}
		if err := json.Unmarshal(r, &top); err != nil {
			return nil, errEngineAnswer
		}
	}
	var out struct {
		Allowed       *bool            `json:"allowed"`
		ReasonCode    string           `json:"reason_code"`
		Obligations   []map[string]any `json:"obligations"`
		PolicyVersion string           `json:"policy_version"`
	}
	b, _ := json.Marshal(top)
	if err := json.Unmarshal(b, &out); err != nil || out.Allowed == nil || len(out.ReasonCode) > 64 || len(out.PolicyVersion) > 128 {
		return nil, errEngineAnswer
	}
	return &engineVerdict{Allowed: *out.Allowed, ReasonCode: out.ReasonCode, Obligations: out.Obligations, PolicyVersion: out.PolicyVersion}, nil
}
