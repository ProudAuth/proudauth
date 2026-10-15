package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/oauth"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/realm"
)

// proofFrom extracts continuation authority. Headless clients send the
// continuation in X-Transaction-Token; browser login surfaces rely on the HttpOnly
// transaction cookie plus a CSRF header and an allowed Origin (AUT-003, SEC-002).
func (a *App) proofFrom(r *http.Request, rlm *realm.Realm, mutating bool) (authentication.Proof, error) {
	if t := r.Header.Get("X-Transaction-Token"); t != "" {
		return authentication.Proof{Continuation: t, RememberedDevice: r.Header.Get("X-Remembered-Device")}, nil
	}
	c, err := r.Cookie(cookieTransaction)
	if err != nil || c.Value == "" {
		return authentication.Proof{}, problem.ErrTransactionInvalid
	}
	if mutating && !a.originAllowed(r, rlm) {
		return authentication.Proof{}, problem.ErrForbidden.WithDetail("origin not allowed")
	}
	p := authentication.Proof{Continuation: c.Value, CSRF: r.Header.Get("X-CSRF-Token"), Browser: true}
	if rd, err := r.Cookie(cookieRememberedDevice); err == nil {
		p.RememberedDevice = rd.Value
	}
	return p, nil
}

type startBody struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	Scope               string   `json:"scope"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	Prompt              string   `json:"prompt"`
	MaxAge              string   `json:"max_age"`
	ACRValues           string   `json:"acr_values"`
	LoginHint           string   `json:"login_hint"`
	UILocales           string   `json:"ui_locales"`
	Organization        string   `json:"organization"`
	Resource            []string `json:"resource"`
	Intent              string   `json:"intent"`
	RequestURI          string   `json:"request_uri"`
	DeviceUserCode      string   `json:"device_user_code"`
	// Claims is the OIDC claims request (OIDC-008).
	Claims string `json:"claims"`
	// ResponseMode is query (default), or jwt / query.jwt for JWT-secured
	// authorization responses (ADV-002).
	ResponseMode string `json:"response_mode"`
}

// startTransaction implements POST R/auth/transactions (AUT-001).
func (a *App) startTransaction(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	a.applyCORS(w, r, rlm, true)
	var b startBody
	if err := decode(r, &b); err != nil {
		return err
	}
	info := reqctx.From(r.Context())
	if b.DeviceUserCode != "" {
		st, details, err := a.OAuth.StartDeviceTransaction(r.Context(), rlm, b.DeviceUserCode, info.ClientIP, info.UserAgent)
		if err != nil {
			return err
		}
		state, err := a.Auth.View(r.Context(), rlm.ID, st.Transaction.ID, authentication.Proof{Continuation: st.Continuation})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"transaction_id": st.Transaction.ID, "continuation_token": st.Continuation,
			"device_request": details, "state": state})
		return nil
	}
	req := oauth.AuthorizeRequest{ClientID: b.ClientID, RedirectURI: b.RedirectURI, ResponseType: "code", Scope: b.Scope, State: b.State,
		Nonce: b.Nonce, CodeChallenge: b.CodeChallenge, CodeChallengeMethod: b.CodeChallengeMethod, Prompt: b.Prompt, MaxAge: b.MaxAge,
		ACRValues: b.ACRValues, LoginHint: b.LoginHint, UILocales: b.UILocales, Organization: b.Organization, Resources: b.Resource,
		Intent: b.Intent, RequestURI: b.RequestURI, Claims: b.Claims, ResponseMode: b.ResponseMode}
	st, err := a.OAuth.StartHeadless(r.Context(), rlm, req, info.ClientIP, info.UserAgent)
	if err != nil {
		return err
	}
	state, err := a.Auth.View(r.Context(), rlm.ID, st.Transaction.ID, authentication.Proof{Continuation: st.Continuation})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{"transaction_id": st.Transaction.ID, "continuation_token": st.Continuation, "state": state})
	return nil
}

func (a *App) getTransaction(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
	a.applyCORS(w, r, rlm, true)
	p, err := a.proofFrom(r, rlm, false)
	if err != nil {
		return err
	}
	st, err := a.Auth.View(r.Context(), rlm.ID, r.PathValue("id"), p)
	if err != nil {
		return err
	}
	if p.Browser {
		// The CSRF token is readable only by an allowed origin through CORS.
		if tok, err := a.Auth.CSRFToken(r.Context(), rlm.ID, r.PathValue("id"), p); err == nil {
			st.CSRF = tok
		}
	}
	writeJSON(w, http.StatusOK, st)
	return nil
}

// step adapts a transaction step to HTTP.
func (a *App) step(fn func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error)) http.HandlerFunc {
	return a.public(func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		a.applyCORS(w, r, rlm, true)
		p, err := a.proofFrom(r, rlm, true)
		if err != nil {
			return err
		}
		st, err := fn(r, rlm, r.PathValue("id"), p)
		if err != nil {
			if pe, ok := problem.As(err); ok && pe.Code == problem.ErrInvalidCredentials.Code {
				a.Metrics.Logins.Inc("failure")
			}
			return err
		}
		if st.Completion != nil {
			a.Metrics.Logins.Inc("success")
			if p.Browser {
				if st.SessionCookie != "" {
					maxAge := a.D.Cfg.Sessions.AbsoluteTimeout
					if st.Completion.Transient {
						maxAge = 0 // browser-session cookie (SES-020)
					}
					http.SetCookie(w, a.cookie(cookieSession, st.SessionCookie, realmPath(rlm), maxAge))
				}
				maxAge := a.D.Cfg.Sessions.AbsoluteTimeout
				if st.Completion.Transient {
					maxAge = 0
				}
				a.setBrowserState(w, rlm, st.Completion.SessionID, maxAge)
				http.SetCookie(w, a.cookie(cookieTransaction, "", txCookiePath(rlm, r.PathValue("id")), -1))
				// Browsers keep the remembered-device secret in an HttpOnly cookie
				// scoped to the transaction API; it never reaches page scripts.
				if rd, ok := st.OneTime["remembered_device_token"].(string); ok && rd != "" {
					http.SetCookie(w, a.cookie(cookieRememberedDevice, rd, txPath(rlm), time.Duration(authentication.RememberDays(rlm.Policy))*24*time.Hour))
					delete(st.OneTime, "remembered_device_token")
				}
			}
		}
		if st.Status == authentication.StatusCancelled || st.Status == authentication.StatusFailed {
			if u, err := a.Auth.ErrorRedirect(r.Context(), rlm.ID, r.PathValue("id"), p); err == nil && u != "" {
				st.RedirectTo = u
			}
		}
		writeJSON(w, http.StatusOK, st)
		return nil
	})
}

type codeBody struct {
	Code string `json:"code"`
}

func (a *App) transactionRoutes(mux *http.ServeMux) {
	base := "/api/v1/realms/{realm}/auth/transactions"
	mux.HandleFunc("POST "+base, a.public(a.startTransaction))
	mux.HandleFunc("GET "+base+"/{id}", a.public(a.getTransaction))
	mux.HandleFunc("POST "+base+"/{id}/identify", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Identifier string `json:"identifier"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.Identify(r.Context(), rlm.ID, id, p, b.Identifier)
	}))
	mux.HandleFunc("POST "+base+"/{id}/password", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Identifier string `json:"identifier"`
			Password   string `json:"password"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.Password(r.Context(), rlm.ID, id, p, b.Identifier, b.Password)
	}))
	mux.HandleFunc("POST "+base+"/{id}/otp/send", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Purpose string `json:"purpose"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.SendOTP(r.Context(), rlm.ID, id, p, b.Purpose)
	}))
	mux.HandleFunc("POST "+base+"/{id}/otp/verify", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b codeBody
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.VerifyOTP(r.Context(), rlm.ID, id, p, b.Code)
	}))
	mux.HandleFunc("POST "+base+"/{id}/totp", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b codeBody
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.TOTP(r.Context(), rlm.ID, id, p, b.Code)
	}))
	// X.509 sign-in (PROV-016): the certificate comes from the TLS
	// connection (mutual-TLS endpoint) or a trusted proxy, never the body.
	mux.HandleFunc("POST "+base+"/{id}/certificate", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		if err := decode(r, &struct{}{}); err != nil {
			return nil, err
		}
		cert, inter := a.peerCertificate(r)
		return a.Auth.Certificate(r.Context(), rlm.ID, id, p, cert, inter)
	}))
	mux.HandleFunc("POST "+base+"/{id}/hotp", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b codeBody
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.HOTP(r.Context(), rlm.ID, id, p, b.Code)
	}))
	// Authentication flow challenges (AUT-012, SEC-014): a provider response or
	// an emailed code, the accessible alternative.
	mux.HandleFunc("POST "+base+"/{id}/challenge", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b authentication.ChallengeInput
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.AnswerChallenge(r.Context(), rlm.ID, id, p, b)
	}))
	mux.HandleFunc("POST "+base+"/{id}/challenge/send", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		if err := decode(r, &struct{}{}); err != nil {
			return nil, err
		}
		return a.Auth.SendChallengeCode(r.Context(), rlm.ID, id, p)
	}))
	mux.HandleFunc("POST "+base+"/{id}/totp/enroll", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		return a.Auth.EnrollTOTP(r.Context(), rlm.ID, id, p)
	}))
	mux.HandleFunc("POST "+base+"/{id}/totp/activate", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b codeBody
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.ActivateTOTP(r.Context(), rlm.ID, id, p, b.Code)
	}))
	mux.HandleFunc("POST "+base+"/{id}/recovery-code", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b codeBody
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.RecoveryCode(r.Context(), rlm.ID, id, p, b.Code)
	}))
	// Passkeys (PASS-001..003): ceremony options and responses. The credential is the
	// PublicKeyCredential JSON produced by the browser or platform API.
	mux.HandleFunc("POST "+base+"/{id}/webauthn/options", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		if err := decode(r, &struct{}{}); err != nil {
			return nil, err
		}
		return a.Auth.WebAuthnOptions(r.Context(), rlm.ID, id, p)
	}))
	mux.HandleFunc("POST "+base+"/{id}/webauthn/verify", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Credential json.RawMessage `json:"credential"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		if len(b.Credential) == 0 {
			return nil, problem.ErrValidation.WithField("credential", "required")
		}
		return a.Auth.WebAuthnVerify(r.Context(), rlm.ID, id, p, b.Credential)
	}))
	mux.HandleFunc("POST "+base+"/{id}/webauthn/registration-options", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		if err := decode(r, &struct{}{}); err != nil {
			return nil, err
		}
		return a.Auth.WebAuthnRegistrationOptions(r.Context(), rlm.ID, id, p)
	}))
	mux.HandleFunc("POST "+base+"/{id}/webauthn/register", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Credential json.RawMessage `json:"credential"`
			Name       string          `json:"name"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		if len(b.Credential) == 0 {
			return nil, problem.ErrValidation.WithField("credential", "required")
		}
		return a.Auth.WebAuthnRegister(r.Context(), rlm.ID, id, p, b.Credential, b.Name)
	}))
	mux.HandleFunc("POST "+base+"/{id}/magic-link", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Token string `json:"token"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.ConsumeMagicLink(r.Context(), rlm.ID, id, p, b.Token)
	}))
	mux.HandleFunc("POST "+base+"/{id}/remember-device", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Remember bool `json:"remember"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.SetRememberDevice(r.Context(), rlm.ID, id, p, b.Remember)
	}))
	mux.HandleFunc("POST "+base+"/{id}/account", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Continue bool `json:"continue"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.SelectAccount(r.Context(), rlm.ID, id, p, b.Continue)
	}))
	mux.HandleFunc("POST "+base+"/{id}/transient", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Transient bool `json:"transient"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.SetTransient(r.Context(), rlm.ID, id, p, b.Transient)
	}))
	mux.HandleFunc("POST "+base+"/{id}/password/update", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			NewPassword string `json:"new_password"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.UpdatePassword(r.Context(), rlm.ID, id, p, b.NewPassword)
	}))
	mux.HandleFunc("POST "+base+"/{id}/terms", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Version string `json:"version"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.AcceptTerms(r.Context(), rlm.ID, id, p, b.Version)
	}))
	// The only step a pending-deletion account reaches after authenticating
	// (USR-012): cancel the scheduled deletion and continue signing in.
	mux.HandleFunc("POST "+base+"/{id}/cancel-deletion", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		if err := decode(r, &struct{}{}); err != nil {
			return nil, err
		}
		return a.Auth.CancelDeletion(r.Context(), rlm.ID, id, p)
	}))
	mux.HandleFunc("POST "+base+"/{id}/profile", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Fields map[string]any `json:"fields"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.CompleteProfile(r.Context(), rlm.ID, id, p, b.Fields)
	}))
	mux.HandleFunc("POST "+base+"/{id}/organization", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			OrganizationID string `json:"organization_id"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.SelectOrganization(r.Context(), rlm.ID, id, p, b.OrganizationID)
	}))
	mux.HandleFunc("POST "+base+"/{id}/consent", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Approve bool     `json:"approve"`
			Scopes  []string `json:"scopes"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.Consent(r.Context(), rlm.ID, id, p, b.Approve, b.Scopes)
	}))
	mux.HandleFunc("POST "+base+"/{id}/remember-me", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b struct {
			Remember bool `json:"remember"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.SetRememberMe(r.Context(), rlm.ID, id, p, b.Remember)
	}))
	mux.HandleFunc("POST "+base+"/{id}/guest", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		return a.Auth.Guest(r.Context(), rlm.ID, id, p)
	}))
	mux.HandleFunc("POST "+base+"/{id}/cancel", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		return a.Auth.Cancel(r.Context(), rlm.ID, id, p)
	}))
	// Browser login surfaces register through the transaction's own path: the
	// transaction cookie is scoped to /auth/transactions/{id} (AUT-016), so it
	// never reaches the realm-level route below, which serves headless clients.
	mux.HandleFunc("POST "+base+"/{id}/registration", a.step(func(r *http.Request, rlm *realm.Realm, id string, p authentication.Proof) (*authentication.State, error) {
		var b authentication.RegistrationInput
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return a.Auth.Register(r.Context(), rlm.ID, id, p, b)
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/registrations", a.public(func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		a.applyCORS(w, r, rlm, true)
		var b struct {
			TransactionID string `json:"transaction_id"`
			authentication.RegistrationInput
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		p, err := a.proofFrom(r, rlm, true)
		if err != nil {
			return err
		}
		st, err := a.Auth.Register(r.Context(), rlm.ID, b.TransactionID, p, b.RegistrationInput)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, st)
		return nil
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/password-resets", a.public(func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		a.applyCORS(w, r, rlm, false)
		var b struct {
			Identifier string `json:"identifier"`
			Locale     string `json:"locale"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		res, err := a.Auth.RequestPasswordReset(r.Context(), rlm.ID, b.Identifier, reqctx.From(r.Context()).ClientIP, b.Locale)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, res)
		return nil
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/password-resets/complete", a.public(func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		a.applyCORS(w, r, rlm, false)
		var b struct {
			ResetID     string `json:"reset_id"`
			Code        string `json:"code"`
			NewPassword string `json:"new_password"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Auth.CompletePasswordReset(r.Context(), rlm.ID, b.ResetID, b.Code, b.NewPassword, reqctx.From(r.Context()).ClientIP); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "password_reset", "mfa_unchanged": true})
		return nil
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/account-setup", a.public(func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		var b struct {
			SetupToken string `json:"setup_token"`
			Password   string `json:"password"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Auth.CompleteAccountSetup(r.Context(), rlm.ID, strings.TrimSpace(b.SetupToken), b.Password, reqctx.From(r.Context()).ClientIP); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "account_ready"})
		return nil
	}))
}
