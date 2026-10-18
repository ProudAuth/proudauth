package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/oauth"
	"github.com/proudauth/proudauth/internal/passkey"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/session"
)

func selfView(u *identity.User, schema *identity.AttributeSchema) map[string]any {
	ids := []map[string]any{}
	for _, i := range u.Identifiers {
		ids = append(ids, map[string]any{"id": i.ID, "type": i.Type, "value": i.Value, "verified": i.Verified(), "is_primary": i.IsPrimary})
	}
	return map[string]any{"id": u.ID, "state": u.State, "display_name": u.DisplayName, "given_name": u.GivenName, "family_name": u.FamilyName,
		"locale": u.Locale, "zoneinfo": u.Zoneinfo, "profile": schema.Visible(u.Profile, "self"), "identifiers": ids, "required_actions": u.RequiredActions,
		"created_at": u.CreatedAt, "updated_at": u.UpdatedAt, "version": u.Version, "deletion_scheduled_at": u.DeletionScheduledAt}
}

func (a *App) selfRoutes(mux *http.ServeMux) {
	base := "/api/v1/realms/{realm}/me"
	mux.HandleFunc("GET "+base, a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		u, err := a.Users.User(r.Context(), nil, p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		setETag(w, u.Version)
		writeJSON(w, http.StatusOK, selfView(u, a.schemaFor(p.Realm.ID)))
		return nil
	}))
	mux.HandleFunc("PATCH "+base, a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var patch identity.ProfilePatch
		if err := decode(r, &patch); err != nil {
			return err
		}
		if a.Hooks != nil {
			proposed := map[string]any{}
			if patch.DisplayName != nil {
				proposed["display_name"] = *patch.DisplayName
			}
			for k, v := range patch.Profile {
				proposed[k] = v
			}
			if err := a.Hooks.CheckProfile(r.Context(), p.Realm.ID, p.SubjectID, proposed); err != nil {
				return err
			}
		}
		ver, err := ifMatch(r, false)
		if err != nil {
			return err
		}
		u, err := a.Users.UpdateProfile(r.Context(), p.Realm.ID, p.SubjectID, ver, patch, p.AuditRef(), a.schemaFor(p.Realm.ID))
		if err != nil {
			return err
		}
		setETag(w, u.Version)
		writeJSON(w, http.StatusOK, selfView(u, a.schemaFor(p.Realm.ID)))
		return nil
	}))
	// Identifiers (USR-004, USR-008).
	mux.HandleFunc("GET "+base+"/identifiers", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		u, err := a.Users.User(r.Context(), nil, p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": selfView(u, nil)["identifiers"]})
		return nil
	}))
	mux.HandleFunc("POST "+base+"/identifiers", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		var b struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		var out *identity.Identifier
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			out, err = a.Users.AddIdentifierTx(r.Context(), tx, p.Realm.ID, p.SubjectID, b.Type, b.Value, false)
			if err != nil {
				return err
			}
			_, err = a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "user.identifier.added", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: p.SubjectID}, Metadata: map[string]any{"identifier_type": b.Type}})
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": out.ID, "type": out.Type, "value": out.Value, "verified": false,
			"next": "POST /verification-challenges to prove control"})
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/identifiers/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			removed, err := a.Users.RemoveIdentifierTx(r.Context(), tx, p.SubjectID, r.PathValue("id"))
			if err != nil {
				return err
			}
			_, err = a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "user.identifier.removed", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: p.SubjectID}, Metadata: map[string]any{"identifier_type": removed.Type}})
			return err
		}); err != nil {
			return err
		}
		// Respond only after the transaction committed.
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/identifiers/{id}/primary", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			if err := a.Users.PromoteIdentifierTx(r.Context(), tx, p.SubjectID, r.PathValue("id")); err != nil {
				return err
			}
			_, err := a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "user.identifier.primary_changed", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: p.SubjectID}})
			return err
		}); err != nil {
			return err
		}
		// Respond only after the transaction committed.
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Guest upgrade (REG-010): the same account becomes registered once the
	// address is verified through the ordinary identifier challenge.
	mux.HandleFunc("POST "+base+"/upgrade", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		id, err := a.Auth.UpgradeGuest(r.Context(), p.Realm.ID, p.ClientID, p.SubjectID, b.Email, b.Password)
		if err != nil {
			return err
		}
		resp := map[string]any{"status": "verify_email", "next": "POST /verification-challenges with the identifier, then consume the emailed code"}
		if id != "" {
			resp["identifier_id"] = id
		}
		writeJSON(w, http.StatusAccepted, resp)
		return nil
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/verification-challenges", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			IdentifierID string `json:"identifier_id"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		id, err := a.Auth.IdentifierChallenge(r.Context(), p.Realm.ID, p.SubjectID, b.IdentifierID, reqctx.From(r.Context()).ClientIP, p.ClientRef, p.OrgID)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"challenge_id": id})
		return nil
	}))
	mux.HandleFunc("POST /api/v1/realms/{realm}/verification-challenges/{id}/consume", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b codeBody
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Auth.ConsumeIdentifierChallenge(r.Context(), p.Realm.ID, p.SubjectID, r.PathValue("id"), b.Code, reqctx.From(r.Context()).ClientIP); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"verified": true})
		return nil
	}))
	// Password change (CRED-006).
	mux.HandleFunc("POST "+base+"/password", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		var b struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Auth.ChangePassword(r.Context(), p.Realm.ID, p.SubjectID, p.SessionID, b.CurrentPassword, b.NewPassword); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "password_changed"})
		return nil
	}))
	// Credentials (safe metadata only).
	mux.HandleFunc("GET "+base+"/credentials", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		rows, err := a.D.DB.Pool.Query(r.Context(), `SELECT id, type, coalesce(name,''), state, created_at, last_used_at FROM credentials
			WHERE user_id=$1 AND state IN ('active','compromised') ORDER BY created_at`, p.SubjectID)
		if err != nil {
			return err
		}
		items := []map[string]any{}
		for rows.Next() {
			var id, typ, name, state string
			var created time.Time
			var used *time.Time
			if err := rows.Scan(&id, &typ, &name, &state, &created, &used); err != nil {
				rows.Close()
				return err
			}
			items = append(items, map[string]any{"id": id, "type": typ, "name": name, "state": state, "created_at": created, "last_used_at": used})
		}
		rows.Close()
		wrows, err := a.D.DB.Pool.Query(r.Context(), `SELECT id, coalesce(name,''), backup_eligible, backup_state, user_verified, created_at, last_used_at
			FROM webauthn_credentials WHERE user_id=$1 AND state='active'`, p.SubjectID)
		if err != nil {
			return err
		}
		for wrows.Next() {
			var id, name string
			var be, bs, uv bool
			var created time.Time
			var used *time.Time
			if err := wrows.Scan(&id, &name, &be, &bs, &uv, &created, &used); err != nil {
				wrows.Close()
				return err
			}
			items = append(items, map[string]any{"id": id, "type": "webauthn", "name": name, "synced": bs, "backup_eligible": be,
				"user_verifying": uv, "created_at": created, "last_used_at": used})
		}
		wrows.Close()
		var remaining int
		_ = a.D.DB.Pool.QueryRow(r.Context(), `SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND state='active'`, p.SubjectID).Scan(&remaining)
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "recovery_codes_remaining": remaining})
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/credentials/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.removeOwnCredential(r, p, r.PathValue("id")); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Remembered devices (AUT-013).
	mux.HandleFunc("GET "+base+"/remembered-devices", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		items, err := a.Auth.ListRememberedDevices(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, items)
	}))
	mux.HandleFunc("DELETE "+base+"/remembered-devices/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.Auth.RevokeRememberedDevices(r.Context(), nil, p.Realm.ID, p.SubjectID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/remembered-devices", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		n, err := a.Auth.RevokeRememberedDevices(r.Context(), nil, p.Realm.ID, p.SubjectID, "", p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
		return nil
	}))
	// Passkeys (PASS-001, PASS-004): enrollment requires recent authentication.
	mux.HandleFunc("GET "+base+"/webauthn", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		items, err := a.Passkeys.List(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		rp, _ := a.Passkeys.RelyingPartyFor(p.Realm)
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "rp_id": rp.ID})
		return nil
	}))
	mux.HandleFunc("POST "+base+"/webauthn/registration-options", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.requireFactorAuthority(r, p); err != nil {
			return err
		}
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		if !p.Realm.Policy.Login.Passkeys && !slices.Contains(p.Realm.Policy.MFA.AllowedFactors, "webauthn") {
			return problem.ErrFeatureDisabled
		}
		// User verification is required when phishing-resistant MFA is, by
		// the realm policy or by the operator floor, as sign-in decides it
		// (MFA-003): a realm policy that predates the floor must not let an
		// unverified passkey be enrolled that sign-in would then refuse.
		requireUV := p.Realm.Policy.MFA.AdminPhishingResistant || a.D.Cfg.Security.MFAFloor.AdminPhishingResistant
		var opts *passkey.RegistrationOptions
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			opts, err = a.Passkeys.BeginRegistration(r.Context(), tx, p.Realm, p.SubjectID, "", requireUV)
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, opts)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/webauthn/registration-complete", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.requireFactorAuthority(r, p); err != nil {
			return err
		}
		var b struct {
			CeremonyID string          `json:"ceremony_id"`
			Credential json.RawMessage `json:"credential"`
			Name       string          `json:"name"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.CeremonyID == "" || len(b.Credential) == 0 {
			return problem.ErrValidation.WithField("credential", "ceremony_id and credential are required")
		}
		var cred *passkey.Credential
		var proofErr error
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			c, f, err := a.Passkeys.FinishRegistration(r.Context(), tx, p.Realm, p.SubjectID, b.CeremonyID, "", b.Credential, b.Name, p.AuditRef())
			if passkey.IsProofFailure(err) {
				proofErr = err // commit the failure evidence (MFA-012)
				return nil
			}
			if err != nil {
				return err
			}
			cred = c
			// Possession of the new authenticator restores assurance for this session.
			if _, err := a.Sessions.StepUpTx(r.Context(), tx, p.SessionID, []session.Factor{f}, false); err != nil {
				return err
			}
			if err := a.restoreAssuranceTx(r.Context(), tx, p); err != nil {
				return err
			}
			// A passkey satisfies a forced second-factor enrollment, as TOTP does.
			if err := a.Users.RemoveRequiredActionTx(r.Context(), tx, p.SubjectID, identity.ActionConfigureTOTP); err != nil {
				return err
			}
			return a.Auth.NotifyMFAChange(r.Context(), tx, p.Realm.ID, p.SubjectID, "a passkey was added to your account")
		})
		if err != nil {
			return err
		}
		if proofErr != nil {
			return errors.Unwrap(proofErr)
		}
		writeJSON(w, http.StatusCreated, cred)
		return nil
	}))
	mux.HandleFunc("PATCH "+base+"/webauthn/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Name string `json:"name"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Passkeys.Rename(r.Context(), p.Realm.ID, p.SubjectID, r.PathValue("id"), b.Name, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// TOTP (MFA-001, MFA-006).
	mux.HandleFunc("POST "+base+"/totp/enroll", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.requireFactorAuthority(r, p); err != nil {
			return err
		}
		u, err := a.Users.User(r.Context(), nil, p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		account := u.Username()
		if e := u.PrimaryEmail(); e != nil {
			account = e.Value
		}
		var en *authentication.TOTPEnrollment
		err = a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			en, err = a.Auth.BeginTOTPTx(r.Context(), tx, p.Realm.ID, p.SubjectID, p.Realm.DisplayName, account)
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, en)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/totp/activate", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.requireFactorAuthority(r, p); err != nil {
			return err
		}
		var b codeBody
		if err := decode(r, &b); err != nil {
			return err
		}
		var codes []string
		var proofErr error
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			proofErr = nil
			codes, _, err = a.Auth.ActivateTOTPTx(r.Context(), tx, p.Realm.ID, p.SubjectID, b.Code, a.D.Cfg.Security.RecoveryCodeCount)
			if authentication.IsProofFailure(err) {
				proofErr = err // commit the failure evidence (MFA-012)
				return nil
			}
			if err != nil {
				return err
			}
			// Assurance restored: a recovery-restricted session regains normal privileges (MFA-010).
			if _, err = a.Sessions.StepUpTx(r.Context(), tx, p.SessionID, []session.Factor{{Type: "totp", At: a.D.Now()}}, false); err != nil {
				return err
			}
			return a.restoreAssuranceTx(r.Context(), tx, p)
		})
		if err != nil {
			return unwrapProof(err)
		}
		if proofErr != nil {
			return unwrapProof(proofErr)
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "totp_enrolled", "recovery_codes": codes})
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/totp", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.guardFactorRemoval(r, p, "totp"); err != nil {
			return err
		}
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			return a.Auth.RemoveTOTPTx(r.Context(), tx, p.Realm.ID, p.SubjectID, p.AuditRef())
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// HOTP (MFA-013): optional counter-based tokens, only in realms that list
	// hotp in allowed_factors; enrollment needs the same authority as TOTP.
	hotpAllowed := func(p *Principal) error {
		if !p.Realm.Policy.MFA.HOTPAllowed() {
			return problem.ErrConflict.WithDetail("counter-based tokens (hotp) are not an allowed factor in this realm")
		}
		return nil
	}
	mux.HandleFunc("POST "+base+"/hotp/enroll", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := hotpAllowed(p); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.requireFactorAuthority(r, p); err != nil {
			return err
		}
		u, err := a.Users.User(r.Context(), nil, p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		account := u.Username()
		if e := u.PrimaryEmail(); e != nil {
			account = e.Value
		}
		var en *authentication.HOTPEnrollment
		err = a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			en, err = a.Auth.BeginHOTPTx(r.Context(), tx, p.Realm.ID, p.SubjectID, p.Realm.DisplayName, account)
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, en)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/hotp/activate", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := hotpAllowed(p); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.requireFactorAuthority(r, p); err != nil {
			return err
		}
		var b codeBody
		if err := decode(r, &b); err != nil {
			return err
		}
		var codes []string
		var proofErr error
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			proofErr = nil
			codes, _, err = a.Auth.ActivateHOTPTx(r.Context(), tx, p.Realm.ID, p.SubjectID, b.Code, p.Realm.Policy.MFA.HOTPLookAhead(),
				a.D.Cfg.Security.RecoveryCodeCount)
			if authentication.IsProofFailure(err) {
				proofErr = err // commit the failure evidence (MFA-012)
				return nil
			}
			if err != nil {
				return err
			}
			if _, err = a.Sessions.StepUpTx(r.Context(), tx, p.SessionID, []session.Factor{{Type: "hotp", At: a.D.Now()}}, false); err != nil {
				return err
			}
			return a.restoreAssuranceTx(r.Context(), tx, p)
		})
		if err != nil {
			return unwrapProof(err)
		}
		if proofErr != nil {
			return unwrapProof(proofErr)
		}
		out := map[string]any{"status": "hotp_enrolled"}
		if len(codes) > 0 {
			out["recovery_codes"] = codes
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	// Resynchronization needs two consecutive codes within the realm's
	// bounded window; a session that completed MFA may do it (the token is
	// out of step, so it cannot be the factor that proves it). Only such a
	// session may, as for regenerating recovery codes: moving the counter of
	// a second factor is a factor change.
	mux.HandleFunc("POST "+base+"/hotp/resync", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := hotpAllowed(p); err != nil {
			return err
		}
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var b struct {
			Code     string `json:"code"`
			NextCode string `json:"next_code"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Code == "" || b.NextCode == "" {
			return problem.ErrValidation.WithDetail("give two consecutive codes: code and next_code")
		}
		// A resynchronization searches a wide window, so attempts are few and
		// the budget fails closed.
		d, err := a.Limiter.Hit(r.Context(), ratelimit.Budget{Key: "hotp_resync:" + p.SubjectID, Limit: 5, Window: 15 * time.Minute})
		if err != nil {
			return problem.ErrUnavailable
		}
		if !d.Allowed {
			return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
		}
		var proofErr error
		err = a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			proofErr = nil
			err := a.Auth.ResyncHOTPTx(r.Context(), tx, p.Realm.ID, p.SubjectID, b.Code, b.NextCode, p.Realm.Policy.MFA.HOTPResyncWindow(), p.AuditRef())
			if authentication.IsProofFailure(err) {
				proofErr = err
				return nil
			}
			return err
		})
		if err != nil {
			return unwrapProof(err)
		}
		if proofErr != nil {
			return unwrapProof(proofErr)
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "hotp_resynchronized"})
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/hotp", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		if err := a.guardFactorRemoval(r, p, "hotp"); err != nil {
			return err
		}
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			return a.Auth.RemoveHOTPTx(r.Context(), tx, p.Realm.ID, p.SubjectID, p.AuditRef())
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/recovery-codes/regenerate", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 5*time.Minute); err != nil {
			return err
		}
		if !p.Session.HasMFA() {
			return problem.ErrMFARequired
		}
		var codes []string
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			codes, err = a.Auth.RegenerateRecoveryCodesTx(r.Context(), tx, p.Realm.ID, p.SubjectID, a.D.Cfg.Security.RecoveryCodeCount)
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
		return nil
	}))
	// Sessions (SES-003, SES-005).
	mux.HandleFunc("GET "+base+"/sessions", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Sessions.ListForUser(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		out := []map[string]any{}
		for _, s := range list {
			out = append(out, map[string]any{"id": s.ID, "current": s.ID == p.SessionID, "created_at": s.CreatedAt, "last_activity_at": s.LastActivityAt,
				"expires_at": s.AbsoluteExpiresAt, "amr": s.AMR, "acr": s.ACR, "user_agent": s.UserAgent, "remember_me": s.RememberMe,
				"recovery_restricted": s.RecoveryRestricted, "device": s.DeviceLabel, "network": s.ClientIP})
		}
		return a.writeList(w, r, out)
	}))
	mux.HandleFunc("DELETE "+base+"/sessions/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		sess, err := a.Sessions.Get(r.Context(), nil, p.Realm.ID, r.PathValue("id"))
		if err != nil || sess.UserID != p.SubjectID {
			return problem.ErrNotFound
		}
		err = a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			if err := a.Sessions.RevokeTx(r.Context(), tx, p.Realm.ID, sess.ID, "user_revoked"); err != nil {
				return err
			}
			_, err := a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "session.revoked_by_user", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: p.SubjectID}, SessionID: sess.ID})
			return err
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/sessions/revoke-all", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var n int
		err := a.D.DB.Tx(r.Context(), func(tx pgx.Tx) error {
			var err error
			n, err = a.Sessions.RevokeUserTx(r.Context(), tx, p.Realm.ID, p.SubjectID, "user_logout_all", true)
			if err != nil {
				return err
			}
			_, err = a.D.Audit.Record(r.Context(), tx, audit.Event{Type: "session.revoked_all", RealmID: p.Realm.ID, Actor: p.AuditRef(),
				Subject: &audit.Ref{Type: "user", ID: p.SubjectID}, Metadata: map[string]any{"count": n}})
			return err
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked_sessions": n})
		return nil
	}))
	mux.HandleFunc("GET "+base+"/organizations", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Orgs.UserMemberships(r.Context(), p.Realm.ID, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base+"/organization-grants", a.self(a.organizationGrant))
	mux.HandleFunc("GET "+base+"/permissions", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		scope := a.realmScope(p)
		org := r.URL.Query().Get("organization_id")
		if org != "" {
			if _, err := a.Orgs.ActiveMembership(r.Context(), nil, p.Realm.ID, org, p.SubjectID); err != nil {
				return problem.ErrNotFound
			}
			scope = orgScope(org)
		}
		project, err := a.projectParam(r, p, org)
		if err != nil {
			return err
		}
		// "My effective permissions" with provenance (AZ-009); policy
		// definitions are never disclosed, only how many may restrict.
		ex, err := a.Authz.Explain(r.Context(), nil, p.Realm.ID, p.Subject(), scope, authorization.ExplainOptions{ProjectID: project})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, explanationView(ex))
		return nil
	}))
	mux.HandleFunc("GET "+base+"/consents", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Auth.Consents(r.Context(), p.Realm.ID, p.SubjectID, r.URL.Query().Get("history") == "true")
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("DELETE "+base+"/consents/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		// Revoking consent ends the client's grants for this user (APP-013).
		if err := a.Auth.RevokeConsent(r.Context(), p.Realm.ID, p.SubjectID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/security-events", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		// Paged by audit sequence, newest first (API-004): the keyset's time
		// carries the sequence number of the last event returned.
		after, err := a.pageAfter(r)
		if err != nil {
			return err
		}
		var beforeSeq int64
		if after != nil {
			beforeSeq = after.At.UnixNano()
		}
		limit := a.pageLimit(r)
		rows, err := a.D.DB.Pool.Query(r.Context(), `SELECT id, type, occurred_at, outcome, coalesce(actor_type,''), coalesce(actor_id,''),
			coalesce(ip_context,''), coalesce(impersonation_grant_id,''), seq FROM audit_events WHERE realm_id=$1 AND (subject_id=$2 OR actor_id=$2)
			AND category IN ('security','support','account','token') AND ($3 = 0 OR seq < $3) ORDER BY seq DESC LIMIT $4`,
			p.Realm.ID, p.SubjectID, beforeSeq, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		out := []map[string]any{}
		var lastSeq int64
		more := false
		for rows.Next() {
			var id, typ, outcome, actorType, actorID, ipc, imp string
			var at time.Time
			var seq int64
			if err := rows.Scan(&id, &typ, &at, &outcome, &actorType, &actorID, &ipc, &imp, &seq); err != nil {
				return err
			}
			if len(out) == limit {
				more = true
				break
			}
			lastSeq = seq
			ev := map[string]any{"id": id, "type": typ, "occurred_at": at, "outcome": outcome, "network": ipc}
			if actorID != p.SubjectID {
				ev["actor_type"] = actorType // another party acted on the account (e.g. support or an administrator)
			}
			if imp != "" {
				ev["support_grant_id"] = imp
			}
			out = append(out, ev)
		}
		var next *keyset
		if more {
			next = &keyset{At: time.Unix(0, lastSeq).UTC()}
		}
		a.writePage(w, r, out, next)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/deletion-request", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		u, err := a.Users.RequestDeletion(r.Context(), p.Realm.ID, p.SubjectID, a.D.Cfg.Privacy.DeletionGracePeriod, p.AuditRef(), func(tx pgx.Tx) error {
			// Last owners must transfer ownership first (USR-020).
			sole, err := a.Orgs.SoleOwnerships(r.Context(), tx, p.SubjectID)
			if err != nil {
				return err
			}
			if len(sole) > 0 {
				return problem.ErrLastOwner.WithDetail("transfer ownership of your organizations before deleting your account")
			}
			if owned, err := a.Orgs.OwnedResources(r.Context(), tx, p.SubjectID); err != nil {
				return err
			} else if len(owned) > 0 {
				return problem.ErrLastOwner.WithDetail("transfer ownership of your projects, clients and other resources before deleting your account").
					WithExtension("owned", owned)
			}
			return nil
		}, func(tx pgx.Tx, u *identity.User) error {
			// The deletion_scheduled notice commits with the request
			// (MSG-002): it names the time and that signing in cancels it.
			// Signing in then reaches only the cancel_deletion step (USR-012).
			if u.DeletionScheduledAt == nil {
				return nil
			}
			return a.notifyUserTx(r.Context(), tx, p.Realm, u, notification.TplDeletion,
				map[string]string{"scheduled": notification.Timestamp(*u.DeletionScheduledAt)})
		})
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"state": u.State, "deletion_scheduled_at": u.DeletionScheduledAt})
		return nil
	}))
	// A pending-deletion account holds no session (the request revoked them
	// all and none can be created), so the owner cancels while signing in:
	// the authentication transaction's cancel_deletion step (USR-012). This
	// route is kept for API compatibility and answers 409 when nothing is
	// pending.
	mux.HandleFunc("DELETE "+base+"/deletion-request", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Users.CancelDeletion(r.Context(), p.Realm.ID, p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Personal access tokens (MCH-006).
	mux.HandleFunc("GET "+base+"/personal-tokens", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Machine.ListCredentials(r.Context(), p.Realm.ID, "user", p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base+"/personal-tokens", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requireRecentAuth(p, 0); err != nil {
			return err
		}
		// A token lives up to a year without a session behind it, so an
		// account with a second factor mints one only from a session that
		// proved it: a password alone, or with a remembered device, cannot
		// (MCH-006).
		if err := a.requireFactorProof(r, p, "verify your second factor before creating a personal access token"); err != nil {
			return err
		}
		var in struct {
			Name           string   `json:"name"`
			Audience       string   `json:"audience"`
			Scopes         []string `json:"scopes"`
			OrganizationID string   `json:"organization_id"`
			TTLDays        int      `json:"ttl_days"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		plain, c, err := a.Machine.CreateCredential(r.Context(), p.Realm.ID, "personal_token", "user", p.SubjectID,
			machineInput(in.Name, in.Audience, in.Scopes, in.OrganizationID, in.TTLDays), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, map[string]any{"token": plain, "credential": c, "notice": "The token is shown only once."})
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/personal-tokens/{id}", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Machine.RevokeCredential(r.Context(), p.Realm.ID, r.PathValue("id"), "user", p.SubjectID, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	// Support-access visibility and control (IMP-021, TEST-071).
	mux.HandleFunc("GET "+base+"/impersonation-grants", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		list, err := a.Imp.List(r.Context(), p.Realm.ID, "", p.SubjectID, "", "")
		if err != nil {
			return err
		}
		out := []map[string]any{}
		for _, g := range list {
			out = append(out, map[string]any{"id": g.ID, "organization_id": g.OrganizationID, "mode": g.Mode, "state": g.State,
				"expires_at": g.ExpiresAt, "created_at": g.CreatedAt, "revoked_at": g.RevokedAt})
		}
		return a.writeList(w, r, out)
	}))
	mux.HandleFunc("POST "+base+"/impersonation-grants/{id}/revoke", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.Imp.Revoke(r.Context(), p.Realm, impActor(p), r.PathValue("id"), "customer_revoked"); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("PUT "+base+"/support-access", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			OptOut bool `json:"opt_out"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if err := a.Imp.SetCustomerOptOut(r.Context(), p.Realm, p.SubjectID, b.OptOut); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"opt_out": b.OptOut})
		return nil
	}))
}

func unwrapProof(err error) error {
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		if pe, ok := problem.As(u.Unwrap()); ok {
			return pe
		}
	}
	return err
}

// restoreAssuranceTx returns a recovery-restricted account to active once a
// new strong factor is enrolled (MFA-010, USR-003).
func (a *App) restoreAssuranceTx(ctx context.Context, tx pgx.Tx, p *Principal) error {
	u, err := a.Users.User(ctx, tx, p.Realm.ID, p.SubjectID)
	if err != nil || u.State != identity.StateRecoveryRestricted {
		return err
	}
	_, err = a.Users.SetStateTx(ctx, tx, p.Realm.ID, p.SubjectID, identity.StateActive, p.AuditRef(), "FACTOR_ASSURANCE_RESTORED")
	return err
}

// requireFactorAuthority lets a session add or replace a second factor only
// when it proved one of the account's existing factors (MFA-006): a password
// plus a remembered device, or a password alone, cannot install an
// attacker's authenticator on an account that already has one. A session that
// used a recovery code holds that proof (MFA-010 lets it enroll anew). A
// code factor the realm no longer allows cannot be proved, so it is not an
// existing factor here (MFA-005).
func (a *App) requireFactorAuthority(r *http.Request, p *Principal) error {
	return a.requireFactorProof(r, p, "verify an existing factor before adding another")
}

// requireFactorProof refuses a session that did not complete MFA when the
// account holds a second factor the realm allows (TOTP, HOTP or a passkey),
// with 403 step_up_required, detail and a reauthenticate obligation for the
// mfa profile. Accounts without such a factor pass.
func (a *App) requireFactorProof(r *http.Request, p *Principal, detail string) error {
	if p.Session == nil || p.Session.HasMFA() {
		return nil
	}
	var enrolled bool
	if err := a.D.DB.Pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM credentials WHERE user_id=$1 AND type = ANY($2) AND state='active')
		OR EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id=$1 AND state='active')`, p.SubjectID, p.Realm.Policy.MFA.CodeFactors()).Scan(&enrolled); err != nil {
		return err
	}
	if enrolled {
		return problem.ErrStepUpRequired.WithDetail(detail).
			WithExtension("obligations", []map[string]any{{"type": "reauthenticate", "required_profile": "mfa"}})
	}
	return nil
}

// guardFactorRemoval prevents removing the last factor when MFA is mandatory for the
// user (FED-011 analogue for factors, PASS-005). Only factors the realm
// allows count as remaining: a disallowed TOTP or HOTP satisfies nothing
// (MFA-005), so it cannot be what keeps the account multi-factor.
func (a *App) guardFactorRemoval(r *http.Request, p *Principal, removing string) error {
	var codes, passkeys int
	allowed := p.Realm.Policy.MFA.CodeFactors()
	_ = a.D.DB.Pool.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM credentials WHERE user_id=$1 AND type = ANY($2) AND state='active'),
		(SELECT count(*) FROM webauthn_credentials WHERE user_id=$1 AND state='active')`, p.SubjectID, allowed).Scan(&codes, &passkeys)
	switch {
	case removing == "totp" || removing == "hotp":
		if !slices.Contains(allowed, removing) {
			return nil // removing a factor that satisfies nothing loses nothing
		}
		codes--
	default:
		passkeys--
	}
	if codes+passkeys > 0 {
		return nil
	}
	privileged, _ := a.Authz.HoldsPrivilegedRealmRole(r.Context(), nil, p.Realm.ID, p.SubjectID)
	if privileged || p.Realm.Policy.MFA.Requirement == "required" {
		return problem.ErrLastMethod.WithDetail("multi-factor authentication is mandatory for this account")
	}
	return nil
}

func (a *App) removeOwnCredential(r *http.Request, p *Principal, id string) error {
	ctx := r.Context()
	var typ string
	if err := a.D.DB.Pool.QueryRow(ctx, `SELECT type FROM credentials WHERE user_id=$1 AND id=$2 AND state='active'`, p.SubjectID, id).Scan(&typ); err == nil {
		switch typ {
		case "password":
			return problem.ErrLastMethod.WithDetail("change the password instead of removing it")
		case "totp":
			if err := a.guardFactorRemoval(r, p, typ); err != nil {
				return err
			}
			return a.D.DB.Tx(ctx, func(tx pgx.Tx) error { return a.Auth.RemoveTOTPTx(ctx, tx, p.Realm.ID, p.SubjectID, p.AuditRef()) })
		case "hotp":
			if err := a.guardFactorRemoval(r, p, typ); err != nil {
				return err
			}
			return a.D.DB.Tx(ctx, func(tx pgx.Tx) error { return a.Auth.RemoveHOTPTx(ctx, tx, p.Realm.ID, p.SubjectID, p.AuditRef()) })
		default:
			return problem.ErrConflict.WithDetail("this credential type cannot be removed here")
		}
	}
	var exists bool
	if err := a.D.DB.Pool.QueryRow(ctx, `SELECT true FROM webauthn_credentials WHERE user_id=$1 AND id=$2 AND state='active'`, p.SubjectID, id).Scan(&exists); err != nil {
		return problem.ErrNotFound
	}
	if err := a.guardFactorRemoval(r, p, "webauthn"); err != nil {
		return err
	}
	return a.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		// A passkey-only account must keep a viable sign-in method (FED-011, PASS-005).
		if err := a.Passkeys.RemoveTx(ctx, tx, p.SubjectID, id); err != nil {
			return err
		}
		if _, err := a.D.Audit.Record(ctx, tx, audit.Event{Type: "mfa.webauthn.removed", RealmID: p.Realm.ID, Actor: p.AuditRef(),
			Subject: &audit.Ref{Type: "user", ID: p.SubjectID}, Metadata: map[string]any{"credential_id": id}}); err != nil {
			return err
		}
		var email string
		_ = tx.QueryRow(ctx, `SELECT original_value FROM user_identifiers WHERE user_id=$1 AND type='email' AND verified_at IS NOT NULL ORDER BY is_primary DESC LIMIT 1`, p.SubjectID).Scan(&email)
		if email != "" {
			_, err := a.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: p.Realm.ID, Template: notification.TplMFAChanged, Recipient: email, Mandatory: true,
				UserID: p.SubjectID, Data: map[string]string{"realm": p.Realm.DisplayName, "change": "passkey removed", "time": notification.Timestamp(a.D.Now())}})
			return err
		}
		return nil
	})
}

// organizationGrant switches organization context: it issues a new code bound to the
// current session for the same client after checking active membership and the
// organization's authentication requirements (TEN-005). It never changes tenant
// context from a header alone.
func (a *App) organizationGrant(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var b struct {
		ClientID            string   `json:"client_id"`
		OrganizationID      string   `json:"organization_id"`
		RedirectURI         string   `json:"redirect_uri"`
		CodeChallenge       string   `json:"code_challenge"`
		CodeChallengeMethod string   `json:"code_challenge_method"`
		Scope               string   `json:"scope"`
		Resource            []string `json:"resource"`
		Nonce               string   `json:"nonce"`
		State               string   `json:"state"`
	}
	if err := decode(r, &b); err != nil {
		return err
	}
	ctx := r.Context()
	if b.ClientID != p.ClientID {
		return problem.ErrForbidden.WithDetail("an organization switch is issued only to the requesting client")
	}
	c, err := a.Apps.ClientByClientID(ctx, nil, p.Realm.ID, b.ClientID)
	if err != nil {
		return problem.ErrForbidden
	}
	// The switch issues an authorization code outside a pushed authorization
	// request, so a client that must push its requests (every fapi2 client,
	// ADV-001, whose codes also live at most 60 seconds; high_assurance or
	// require_par) never gets one here: it starts a new pushed request
	// naming the organization, where all of its profile's rules apply.
	if c.FAPI2() || c.TokenPolicy.RequirePAR {
		return problem.ErrForbidden.WithDetail("this client must use pushed authorization requests: switch organizations with a new pushed authorization request naming the organization")
	}
	if !application.MatchRedirect(c.RedirectURIs, b.RedirectURI, c.Type) {
		return problem.ErrValidation.WithField("redirect_uri", "not registered")
	}
	if b.CodeChallengeMethod != "S256" || len(b.CodeChallenge) != 43 {
		return problem.ErrValidation.WithField("code_challenge", "S256 PKCE challenge required")
	}
	scopes, resources, oe := a.OAuth.ResolveScopes(ctx, p.Realm, c, b.Scope, b.Resource, "user")
	if oe != nil {
		return problem.ErrValidation.WithDetail(oe.Code + ": " + oe.Description)
	}
	org, err := a.Orgs.Get(ctx, nil, p.Realm.ID, b.OrganizationID)
	if err != nil {
		return problem.ErrNotFound
	}
	if org.Policy.MFARequired && !p.Session.HasMFA() {
		return problem.ErrStepUpRequired.WithExtension("obligations", []map[string]any{{"type": "reauthenticate", "required_profile": "mfa"}})
	}
	var redirect string
	err = a.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := a.Orgs.LockActiveTx(ctx, tx, p.Realm.ID, org.ID); err != nil {
			return err
		}
		if _, err := a.Orgs.ActiveMembership(ctx, tx, p.Realm.ID, org.ID, p.SubjectID); err != nil {
			return problem.ErrForbidden.WithDetail("no active membership in that organization")
		}
		sess, err := a.Sessions.Active(ctx, tx, p.Realm.ID, p.SessionID)
		if err != nil {
			return problem.ErrUnauthenticated
		}
		// The session must meet the organization's sign-in rules as a login
		// into it would (TEN-005, TEN-012): its required SSO connection, its
		// allowed methods and its session lifetime.
		if a.Auth.ForeignConnection(ctx, tx, p.Realm.ID, sess.Factors, org.ID) {
			return problem.ErrForbidden.WithDetail("the connection used to sign in belongs to another organization")
		}
		if org.Policy.SSORequired && !slices.ContainsFunc(sess.Factors, func(f session.Factor) bool {
			return f.Type == "fed" && (org.Policy.SSOProviderID == "" || f.Upstream == org.Policy.SSOProviderID)
		}) {
			return problem.ErrSSORequired
		}
		if methods := org.Policy.AllowedLoginMethods; len(methods) > 0 && !slices.ContainsFunc(sess.Factors, func(f session.Factor) bool {
			return slices.Contains(methods, authentication.LoginMethodOf(f.Type))
		}) {
			return problem.ErrStepUpRequired.WithDetail("the organization does not allow the sign-in method of this session").
				WithExtension("obligations", []map[string]any{{"type": "reauthenticate", "allowed_login_methods": methods}})
		}
		expires := sess.AbsoluteExpiresAt
		if abs := time.Duration(org.Policy.SessionAbsoluteSeconds) * time.Second; abs > 0 && sess.AuthTime.Add(abs).Before(expires) {
			expires = sess.AuthTime.Add(abs)
		}
		if !a.D.Now().Before(expires) {
			return problem.ErrStepUpRequired.WithDetail("the organization's session lifetime has passed").
				WithExtension("obligations", []map[string]any{{"type": "reauthenticate"}})
		}
		at := sess.AuthTime
		g := &session.Grant{RealmID: p.Realm.ID, SubjectType: "user", SubjectID: p.SubjectID, ClientRef: c.Ref, OrgID: org.ID, SessionID: sess.ID,
			ResourceIDs: resources, Scopes: slices.DeleteFunc(slices.Clone(scopes), func(s string) bool { return s == "offline_access" }),
			AuthTime: &at, AMR: sess.AMR, ACR: sess.ACR, ExpiresAt: expires}
		if err := a.Sessions.CreateGrantTx(ctx, tx, g); err != nil {
			return err
		}
		code, err := a.Sessions.IssueCodeTx(ctx, tx, p.Realm.ID, session.Code{ClientRef: c.Ref, TransactionID: "org-switch:" + sess.ID, GrantID: g.ID,
			RedirectURI: b.RedirectURI, Challenge: b.CodeChallenge, Method: "S256", Nonce: b.Nonce}, a.D.Cfg.Tokens.AuthorizationCodeTTL)
		if err != nil {
			return err
		}
		params := map[string]string{"code": code, "state": b.State, "iss": p.Realm.Issuer}
		if p.Realm.Policy.Sessions.CheckSessionIframe {
			params["session_state"] = session.SessionState(c.ClientID, b.RedirectURI, session.BrowserState(a.D.Keys, sess.ID))
		}
		redirect = authentication.BuildRedirect(b.RedirectURI, params)
		_, err = a.D.Audit.Record(ctx, tx, audit.Event{Type: "organization.context.switched", RealmID: p.Realm.ID, OrgID: org.ID, Actor: p.AuditRef(),
			Subject: &audit.Ref{Type: "user", ID: p.SubjectID}, GrantID: g.ID, ClientID: c.ClientID})
		return err
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"redirect_to": redirect})
	return nil
}

// SchemaFor returns the realm's custom attribute schema (nil when none).
func (a *App) SchemaFor(realmID string) *identity.AttributeSchema { return a.schemaFor(realmID) }

func (a *App) schemaFor(realmID string) *identity.AttributeSchema {
	if a.Auth.Schema == nil {
		return nil
	}
	return a.Auth.Schema(realmID)
}

var _ = strings.TrimSpace
var _ = authorization.ScopeRealm
var _ = oauth.ErrServerError
