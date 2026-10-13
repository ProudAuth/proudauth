package authentication

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/credential"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/storage"
)

// passwordCredential returns the active password verifier.
func (s *Service) passwordCredential(ctx context.Context, q storage.Querier, userID string) (id, verifier, state string, err error) {
	err = q.QueryRow(ctx, `SELECT id, verifier, state FROM credentials WHERE user_id=$1 AND type='password' AND state IN ('active','compromised')
		ORDER BY state LIMIT 1`, userID).Scan(&id, &verifier, &state)
	return
}

// VerifyPassword checks a password and transparently rehashes obsolete verifiers
// (CRED-004). A compromised credential never authenticates (CRED-008).
func (s *Service) VerifyPassword(ctx context.Context, tx pgx.Tx, userID, password string) (bool, error) {
	if s.Directory != nil {
		// A directory-sourced account's password is the directory's: a bind
		// decides, and an outage fails closed instead of consulting a local
		// verifier (PROV-011, PROV-014).
		if handled, ok, err := s.Directory.VerifyPassword(ctx, tx, userID, password); handled || err != nil {
			return ok, err
		}
	}
	id, verifier, state, err := s.passwordCredential(ctx, tx, userID)
	if err != nil {
		if storage.IsNoRows(err) {
			s.Hasher.DummyVerify(password)
			return false, nil
		}
		return false, err
	}
	rehash, err := s.Hasher.Verify(verifier, password)
	if errors.Is(err, credential.ErrLegacyRetired) {
		// The account must recover its password; the reason is evidence.
		_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.password.legacy_retired", Actor: audit.System,
			Subject: &audit.Ref{Type: "user", ID: userID}, Outcome: audit.Failure, ReasonCode: "LEGACY_HASH_RETIRED"})
	}
	if errors.Is(err, credential.ErrPepperUnavailable) {
		// A key problem, not a wrong password (CRED-009): the verifier names a
		// pepper version the keyring lacks. Verification fails closed; the
		// operator learns of it from the log and the audit trail.
		s.d.Log.Error("password verifier references an unavailable pepper version", "user_id", userID, "credential_id", id, "error", err)
		_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.password.pepper_unavailable", Actor: audit.System,
			Subject: &audit.Ref{Type: "user", ID: userID}, Outcome: audit.Failure, ReasonCode: "PEPPER_UNAVAILABLE"})
	}
	if err != nil {
		return false, nil
	}
	if state != "active" {
		return false, nil
	}
	if rehash {
		if nv, err := s.Hasher.Hash(password); err == nil {
			_, _ = tx.Exec(ctx, `UPDATE credentials SET verifier=$2, algorithm='argon2id', updated_at=$3 WHERE id=$1`, id, nv, s.d.Now())
		}
	}
	_, _ = tx.Exec(ctx, `UPDATE credentials SET last_used_at=$2 WHERE id=$1`, id, s.d.Now())
	return true, nil
}

// SetPasswordTx replaces the password verifier after policy checks, recording
// bounded history when configured (CRED-002, CRED-010).
func (s *Service) SetPasswordTx(ctx context.Context, tx pgx.Tx, realmID, userID, password string, minOverride, historyCount int, contextWords ...string) error {
	// The deployment setting is a floor under realm policy (CRED-008).
	if h := s.d.Cfg.Security.Password.HistoryCount; h > historyCount {
		historyCount = h
	}
	// A directory-sourced account's password is changed in the directory;
	// password write-back is not offered (USR-022, PROV-013).
	if a := s.Users.Authority; a != nil && !identity.IsExternalWriter(ctx) {
		if err := a.CheckEdit(ctx, tx, realmID, userID, map[string]any{"password": true}); err != nil {
			return err
		}
	}
	if v := s.Policy.Check(password, minOverride, contextWords...); v != nil {
		return problem.ErrPasswordPolicy.WithDetail(v.Message).WithExtension("policy_code", v.Code)
	}
	if historyCount > 0 {
		rows, err := tx.Query(ctx, `SELECT verifier FROM password_history WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`, userID, historyCount)
		if err != nil {
			return err
		}
		var old []string
		for rows.Next() {
			var v string
			_ = rows.Scan(&v)
			old = append(old, v)
		}
		rows.Close()
		for _, v := range old {
			if _, err := s.Hasher.Verify(v, password); err == nil {
				return problem.ErrPasswordPolicy.WithDetail("Password was used recently.").WithExtension("policy_code", "reused")
			}
		}
	}
	verifier, err := s.Hasher.Hash(password)
	if err != nil {
		return problem.ErrPasswordPolicy.WithDetail("Password cannot be processed.")
	}
	now := s.d.Now()
	var oldVerifier string
	_ = tx.QueryRow(ctx, `SELECT verifier FROM credentials WHERE user_id=$1 AND type='password' AND state IN ('active','compromised') LIMIT 1`, userID).Scan(&oldVerifier)
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked', updated_at=$2 WHERE user_id=$1 AND type='password' AND state IN ('active','compromised')`, userID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, realm_id, user_id, type, state, verifier, algorithm, created_at, updated_at)
		VALUES ($1,$2,$3,'password','active',$4,'argon2id',$5,$5)`, ids.New(ids.Credential), realmID, userID, verifier, now); err != nil {
		return err
	}
	if historyCount > 0 && oldVerifier != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO password_history (id, realm_id, user_id, verifier, created_at) VALUES ($1,$2,$3,$4,$5)`,
			ids.New(ids.PasswordHist), realmID, userID, oldVerifier, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM password_history WHERE user_id=$1 AND id NOT IN (SELECT id FROM password_history WHERE user_id=$1
			ORDER BY created_at DESC LIMIT $2)`, userID, historyCount); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE users SET credential_revision=credential_revision+1, required_actions=array_remove(required_actions, 'update_password'),
		updated_at=$2 WHERE id=$1`, userID, now)
	return err
}

// MarkPasswordCompromised forces recovery (CRED-008).
func (s *Service) MarkPasswordCompromised(ctx context.Context, realmID, userID string, actor audit.Ref, reason string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE credentials SET state='compromised', updated_at=$2 WHERE user_id=$1 AND type='password' AND state='active'`, userID, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		if _, err := s.Sessions.RevokeUserTx(ctx, tx, realmID, userID, "credential_compromised", true); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.password.compromised", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, ReasonCode: reason}); err != nil {
			return err
		}
		_, err = s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "security.credential_compromised", RealmID: realmID, AggregateType: "user",
			AggregateID: userID, Data: map[string]any{"user_id": userID}})
		return err
	})
}

// ---------- TOTP ----------

// TOTPEnrollment is returned once when enrollment begins.
type TOTPEnrollment struct {
	CredentialID string    `json:"credential_id"`
	Secret       string    `json:"secret"`
	URI          string    `json:"otpauth_uri"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// BeginTOTPTx creates a pending TOTP credential with an encrypted seed (MFA-001).
func (s *Service) BeginTOTPTx(ctx context.Context, tx pgx.Tx, realmID, userID, issuer, account string) (*TOTPEnrollment, error) {
	seed := credential.NewTOTPSecret()
	id := ids.New(ids.Credential)
	ct, ver, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(seed), []byte("totp:"+id))
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	exp := now.Add(15 * time.Minute)
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked' WHERE user_id=$1 AND type='totp' AND state='pending'`, userID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, realm_id, user_id, type, name, state, secret_ciphertext, key_version, algorithm, params, expires_at, created_at, updated_at)
		VALUES ($1,$2,$3,'totp','Authenticator app','pending',$4,$5,'SHA1','{"digits":6,"period":30}',$6,$7,$7)`, id, realmID, userID, ct, ver, exp, now); err != nil {
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.totp.enrollment_started", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
		Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"credential_id": id}}); err != nil {
		return nil, err
	}
	return &TOTPEnrollment{CredentialID: id, Secret: seed, URI: credential.TOTPURI(issuer, account, seed), ExpiresAt: exp}, nil
}

// ImportTOTPTx stores a TOTP seed migrated from another system as an active
// factor (MIG-007). The seed is validated, encrypted under this deployment's
// keys bound to the new credential, and audited without the seed.
func (s *Service) ImportTOTPTx(ctx context.Context, tx pgx.Tx, realmID, userID, seed, source string, actor audit.Ref) error {
	norm, err := credential.NormalizeImportedTOTPSeed(seed)
	if err != nil {
		return err
	}
	id := ids.New(ids.Credential)
	ct, ver, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(norm), []byte("totp:"+id))
	if err != nil {
		return err
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, realm_id, user_id, type, name, state, secret_ciphertext, key_version, algorithm, params, created_at, updated_at)
		VALUES ($1,$2,$3,'totp','Authenticator app (imported)','active',$4,$5,'SHA1','{"digits":6,"period":30}',$6,$6)`, id, realmID, userID, ct, ver, now); err != nil {
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.totp.imported", RealmID: realmID, Actor: actor, Subject: &audit.Ref{Type: "user", ID: userID},
		Source: "import", Metadata: map[string]any{"credential_id": id, "source_system": source}})
	return err
}

func (s *Service) totpSeed(id string, ct []byte) (string, error) {
	pt, err := s.d.Keys.Decrypt(keys.PurposeData, ct, []byte("totp:"+id))
	return string(pt), err
}

// ActivateTOTPTx verifies a proof against the pending seed and activates it
// (proof-before-activation, MFA-001). Activation replaces any existing TOTP and
// returns a fresh recovery-code batch shown once (MFA-004).
func (s *Service) ActivateTOTPTx(ctx context.Context, tx pgx.Tx, realmID, userID, code string, recoveryCount int) ([]string, string, error) {
	var id string
	var ct []byte
	var exp time.Time
	err := tx.QueryRow(ctx, `SELECT id, secret_ciphertext, expires_at FROM credentials WHERE user_id=$1 AND type='totp' AND state='pending'
		ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, userID).Scan(&id, &ct, &exp)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, "", problem.ErrUnexpectedStep.WithDetail("no TOTP enrollment in progress")
		}
		return nil, "", err
	}
	if !s.d.Now().Before(exp) {
		return nil, "", problem.ErrInvalidProof.WithDetail("enrollment expired; start again")
	}
	seed, err := s.totpSeed(id, ct)
	if err != nil {
		return nil, "", err
	}
	step, ok := credential.MatchTOTP(seed, code, s.d.Now(), s.d.Cfg.Security.TOTPSkewSteps)
	if !ok {
		_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.totp.proof_failed", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
			Subject: &audit.Ref{Type: "user", ID: userID}, Outcome: audit.Failure})
		return nil, "", errProof(problem.ErrInvalidProof)
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked', updated_at=$2 WHERE user_id=$1 AND type='totp' AND state='active'`, userID, now); err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='active', last_used_step=$2, last_used_at=$3, expires_at=NULL, updated_at=$3 WHERE id=$1`, id, step, now); err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET required_actions=array_remove(required_actions, 'configure_totp'), credential_revision=credential_revision+1 WHERE id=$1`, userID); err != nil {
		return nil, "", err
	}
	codes, err := s.RegenerateRecoveryCodesTx(ctx, tx, realmID, userID, recoveryCount)
	if err != nil {
		return nil, "", err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.totp.enrolled", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
		Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"credential_id": id}}); err != nil {
		return nil, "", err
	}
	if err := s.notifySecurity(ctx, tx, realmID, userID, notification.TplMFAChanged, "authenticator app added"); err != nil {
		return nil, "", err
	}
	return codes, id, nil
}

// VerifyTOTPTx verifies a TOTP code with atomic replay control: a time step can be
// consumed once, so concurrent or repeated submission of the same code fails (MFA-002, TEST-023).
func (s *Service) VerifyTOTPTx(ctx context.Context, tx pgx.Tx, userID, code string) (string, bool, error) {
	var id string
	var ct []byte
	err := tx.QueryRow(ctx, `SELECT id, secret_ciphertext FROM credentials WHERE user_id=$1 AND type='totp' AND state='active'`, userID).Scan(&id, &ct)
	if err != nil {
		if storage.IsNoRows(err) {
			return "", false, nil
		}
		return "", false, err
	}
	seed, err := s.totpSeed(id, ct)
	if err != nil {
		return "", false, err
	}
	step, ok := credential.MatchTOTP(seed, code, s.d.Now(), s.d.Cfg.Security.TOTPSkewSteps)
	if !ok {
		return id, false, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE credentials SET last_used_step=$2, last_used_at=$3 WHERE id=$1 AND (last_used_step IS NULL OR last_used_step < $2)`,
		id, step, s.d.Now())
	if err != nil {
		return id, false, err
	}
	return id, tag.RowsAffected() == 1, nil
}

// RemoveTOTPTx removes the active TOTP credential.
func (s *Service) RemoveTOTPTx(ctx context.Context, tx pgx.Tx, realmID, userID string, actor audit.Ref) error {
	// Devices remembered on the strength of this factor are forgotten too.
	if _, err := s.RevokeRememberedDevices(ctx, tx, realmID, userID, "", actor); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked', updated_at=$2 WHERE user_id=$1 AND type='totp' AND state='active'`, userID, s.d.Now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return problem.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET credential_revision=credential_revision+1 WHERE id=$1`, userID); err != nil {
		return err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.totp.removed", RealmID: realmID, Actor: actor, Subject: &audit.Ref{Type: "user", ID: userID}}); err != nil {
		return err
	}
	return s.notifySecurity(ctx, tx, realmID, userID, notification.TplMFAChanged, "authenticator app removed")
}

// ---------- HOTP (MFA-013) ----------

// HOTPEnrollment is returned once when HOTP enrollment begins.
type HOTPEnrollment struct {
	CredentialID string    `json:"credential_id"`
	Secret       string    `json:"secret"`
	URI          string    `json:"otpauth_uri"`
	Counter      int64     `json:"counter"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// BeginHOTPTx creates a pending HOTP credential (counter 0) with an encrypted
// seed. HOTP is optional compatibility for counter-based tokens; the caller
// checks that the realm lists it in allowed_factors.
func (s *Service) BeginHOTPTx(ctx context.Context, tx pgx.Tx, realmID, userID, issuer, account string) (*HOTPEnrollment, error) {
	seed := credential.NewTOTPSecret()
	id := ids.New(ids.Credential)
	ct, ver, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(seed), []byte("hotp:"+id))
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	exp := now.Add(15 * time.Minute)
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked' WHERE user_id=$1 AND type='hotp' AND state='pending'`, userID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, realm_id, user_id, type, name, state, secret_ciphertext, key_version, algorithm, params, counter, expires_at, created_at, updated_at)
		VALUES ($1,$2,$3,'hotp','Counter-based token','pending',$4,$5,'SHA1','{"digits":6}',0,$6,$7,$7)`, id, realmID, userID, ct, ver, exp, now); err != nil {
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.hotp.enrollment_started", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
		Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"credential_id": id}}); err != nil {
		return nil, err
	}
	return &HOTPEnrollment{CredentialID: id, Secret: seed, URI: credential.HOTPURI(issuer, account, seed, 0), ExpiresAt: exp}, nil
}

func (s *Service) hotpSeed(id string, ct []byte) (string, error) {
	pt, err := s.d.Keys.Decrypt(keys.PurposeData, ct, []byte("hotp:"+id))
	return string(pt), err
}

// ActivateHOTPTx verifies a code from the pending token within the realm's
// look-ahead and activates it, replacing an active HOTP credential. The
// counter moves past the code, so it cannot be used again. Recovery codes are
// issued (shown once) only when the account has none.
func (s *Service) ActivateHOTPTx(ctx context.Context, tx pgx.Tx, realmID, userID, code string, lookAhead, recoveryCount int) ([]string, string, error) {
	var id string
	var ct []byte
	var exp time.Time
	err := tx.QueryRow(ctx, `SELECT id, secret_ciphertext, expires_at FROM credentials WHERE user_id=$1 AND type='hotp' AND state='pending'
		ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, userID).Scan(&id, &ct, &exp)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, "", problem.ErrUnexpectedStep.WithDetail("no HOTP enrollment in progress")
		}
		return nil, "", err
	}
	now := s.d.Now()
	if !now.Before(exp) {
		return nil, "", problem.ErrInvalidProof.WithDetail("enrollment expired; start again")
	}
	seed, err := s.hotpSeed(id, ct)
	if err != nil {
		return nil, "", err
	}
	matched, ok := credential.MatchHOTP(seed, code, 0, lookAhead)
	if !ok {
		_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.hotp.proof_failed", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
			Subject: &audit.Ref{Type: "user", ID: userID}, Outcome: audit.Failure})
		return nil, "", errProof(problem.ErrInvalidProof)
	}
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked', updated_at=$2 WHERE user_id=$1 AND type='hotp' AND state='active'`, userID, now); err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='active', counter=$2, last_used_at=$3, expires_at=NULL, updated_at=$3 WHERE id=$1`, id, matched+1, now); err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET required_actions=array_remove(required_actions, 'configure_totp'), credential_revision=credential_revision+1 WHERE id=$1`, userID); err != nil {
		return nil, "", err
	}
	var codes []string
	var hasCodes bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM recovery_codes WHERE user_id=$1 AND state='active')`, userID).Scan(&hasCodes); err != nil {
		return nil, "", err
	}
	if !hasCodes {
		if codes, err = s.RegenerateRecoveryCodesTx(ctx, tx, realmID, userID, recoveryCount); err != nil {
			return nil, "", err
		}
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.hotp.enrolled", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
		Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"credential_id": id}}); err != nil {
		return nil, "", err
	}
	if err := s.notifySecurity(ctx, tx, realmID, userID, notification.TplMFAChanged, "counter-based token added"); err != nil {
		return nil, "", err
	}
	return codes, id, nil
}

// VerifyHOTPTx verifies a code within the look-ahead and advances the counter
// past it atomically: the row is locked and the update is conditional on the
// counter not having moved, so a code is accepted once even under concurrent
// submission (MFA-013).
func (s *Service) VerifyHOTPTx(ctx context.Context, tx pgx.Tx, userID, code string, lookAhead int) (string, bool, error) {
	var id string
	var ct []byte
	var counter int64
	err := tx.QueryRow(ctx, `SELECT id, secret_ciphertext, coalesce(counter, 0) FROM credentials WHERE user_id=$1 AND type='hotp' AND state='active'
		FOR UPDATE`, userID).Scan(&id, &ct, &counter)
	if err != nil {
		if storage.IsNoRows(err) {
			return "", false, nil
		}
		return "", false, err
	}
	seed, err := s.hotpSeed(id, ct)
	if err != nil {
		return "", false, err
	}
	matched, ok := credential.MatchHOTP(seed, code, counter, lookAhead)
	if !ok {
		return id, false, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE credentials SET counter=$2, last_used_at=$3 WHERE id=$1 AND coalesce(counter, 0)=$4`, id, matched+1, s.d.Now(), counter)
	if err != nil {
		return id, false, err
	}
	return id, tag.RowsAffected() == 1, nil
}

// ResyncHOTPTx realigns the stored counter with a token that was pressed
// beyond the sign-in look-ahead (MFA-013): two consecutive codes are required
// within the bounded resynchronization window, and the counter only moves
// forward.
func (s *Service) ResyncHOTPTx(ctx context.Context, tx pgx.Tx, realmID, userID, code, next string, window int, actor audit.Ref) error {
	var id string
	var ct []byte
	var counter int64
	err := tx.QueryRow(ctx, `SELECT id, secret_ciphertext, coalesce(counter, 0) FROM credentials WHERE user_id=$1 AND type='hotp' AND state='active'
		FOR UPDATE`, userID).Scan(&id, &ct, &counter)
	if err != nil {
		if storage.IsNoRows(err) {
			return problem.ErrNotFound.WithDetail("no counter-based token is enrolled")
		}
		return err
	}
	seed, err := s.hotpSeed(id, ct)
	if err != nil {
		return err
	}
	second, ok := credential.ResyncHOTP(seed, code, next, counter, window)
	if !ok {
		_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.hotp.resync_failed", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Outcome: audit.Failure, Metadata: map[string]any{"credential_id": id}})
		return errProof(problem.ErrInvalidProof.WithDetail("the codes are not two consecutive codes within the resynchronization window"))
	}
	if _, err := tx.Exec(ctx, `UPDATE credentials SET counter=$2, last_used_at=$3, updated_at=$3 WHERE id=$1`, id, second+1, s.d.Now()); err != nil {
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.hotp.resynchronized", RealmID: realmID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"credential_id": id, "advanced_by": second + 1 - counter}})
	return err
}

// RemoveHOTPTx removes the active HOTP credential.
func (s *Service) RemoveHOTPTx(ctx context.Context, tx pgx.Tx, realmID, userID string, actor audit.Ref) error {
	if _, err := s.RevokeRememberedDevices(ctx, tx, realmID, userID, "", actor); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked', updated_at=$2 WHERE user_id=$1 AND type='hotp' AND state='active'`, userID, s.d.Now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return problem.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET credential_revision=credential_revision+1 WHERE id=$1`, userID); err != nil {
		return err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.hotp.removed", RealmID: realmID, Actor: actor, Subject: &audit.Ref{Type: "user", ID: userID}}); err != nil {
		return err
	}
	return s.notifySecurity(ctx, tx, realmID, userID, notification.TplMFAChanged, "counter-based token removed")
}

// ---------- recovery codes ----------

// RegenerateRecoveryCodesTx invalidates all previous codes and creates a new batch
// whose plaintext is returned once; only keyed verifiers are stored (MFA-004).
func (s *Service) RegenerateRecoveryCodesTx(ctx context.Context, tx pgx.Tx, realmID, userID string, n int) ([]string, error) {
	if n <= 0 {
		n = 10
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE recovery_codes SET state='invalidated' WHERE user_id=$1 AND state='active'`, userID); err != nil {
		return nil, err
	}
	batch := ids.New("rcb")
	codes := credential.NewRecoveryCodes(n)
	for _, c := range codes {
		mac, ver := s.d.Keys.MAC(keys.PurposeOTP, "recovery", userID, secret.NormalizeRecoveryCode(c))
		if _, err := tx.Exec(ctx, `INSERT INTO recovery_codes (id, realm_id, user_id, batch_id, code_digest, key_version, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			ids.New(ids.RecoveryCode), realmID, userID, batch, mac, ver, now); err != nil {
			return nil, err
		}
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.recovery_codes.regenerated", RealmID: realmID, Actor: audit.Ref{Type: "user", ID: userID},
		Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"count": n}}); err != nil {
		return nil, err
	}
	return codes, nil
}

// ConsumeRecoveryCodeTx consumes one code atomically (DB-005); concurrent reuse of
// the same code succeeds at most once (TEST-023).
func (s *Service) ConsumeRecoveryCodeTx(ctx context.Context, tx pgx.Tx, userID, code string) (bool, int, error) {
	norm := secret.NormalizeRecoveryCode(code)
	if len(norm) < 10 || len(norm) > 40 {
		return false, 0, nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT key_version FROM recovery_codes WHERE user_id=$1 AND state='active'`, userID)
	if err != nil {
		return false, 0, err
	}
	var versions []int
	for rows.Next() {
		var v int
		_ = rows.Scan(&v)
		versions = append(versions, v)
	}
	rows.Close()
	for _, v := range versions {
		mac := s.d.Keys.MACVersion(keys.PurposeOTP, v, "recovery", userID, norm)
		tag, err := tx.Exec(ctx, `UPDATE recovery_codes SET state='consumed', consumed_at=$3 WHERE user_id=$1 AND code_digest=$2 AND state='active'`,
			userID, mac, s.d.Now())
		if err != nil {
			return false, 0, err
		}
		if tag.RowsAffected() == 1 {
			var remaining int
			_ = tx.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND state='active'`, userID).Scan(&remaining)
			return true, remaining, nil
		}
	}
	return false, 0, nil
}

// notifySecurity enqueues a mandatory security notification to the primary email.
// NotifyMFAChange sends the mandatory security notice for an authenticator change.
func (s *Service) NotifyMFAChange(ctx context.Context, tx pgx.Tx, realmID, userID, change string) error {
	return s.notifySecurity(ctx, tx, realmID, userID, notification.TplMFAChanged, change)
}

func (s *Service) notifySecurity(ctx context.Context, tx pgx.Tx, realmID, userID, tpl, change string) error {
	var email, realmName string
	err := tx.QueryRow(ctx, `SELECT i.original_value, r.display_name FROM user_identifiers i JOIN realms r ON r.id=i.realm_id
		WHERE i.user_id=$1 AND i.type='email' AND i.verified_at IS NOT NULL ORDER BY i.is_primary DESC LIMIT 1`, userID).Scan(&email, &realmName)
	if err != nil {
		return nil // no verified contact: nothing to notify
	}
	_, err = s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: realmID, Template: tpl, Recipient: email, Mandatory: true,
		ReferenceType: "user", ReferenceID: userID, Data: map[string]string{"realm": realmName, "change": change, "time": notification.Timestamp(s.d.Now())}})
	return err
}

// proofError marks a failed proof that must be recorded (failure count, audit)
// while still returning an error to the client.
type proofError struct{ err error }

func (p *proofError) Error() string { return p.err.Error() }
func (p *proofError) Unwrap() error { return p.err }

func errProof(err error) error { return &proofError{err: err} }

// IsProofFailure reports whether err is a failed proof whose evidence the
// caller must commit before returning the error (MFA-012).
func IsProofFailure(err error) bool {
	var pe *proofError
	return errors.As(err, &pe)
}

// ResetFactorsTx revokes every second factor of a user for administrator-
// assisted recovery and requires TOTP enrollment at the next sign-in, so the
// account never becomes MFA-exempt (MFA-009, MFA-010).
func (s *Service) ResetFactorsTx(ctx context.Context, tx pgx.Tx, userID string) error {
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked' WHERE user_id=$1 AND type IN ('totp','hotp') AND state='active'`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE webauthn_credentials SET state='revoked' WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE recovery_codes SET state='invalidated' WHERE user_id=$1 AND state='active'`, userID); err != nil {
		return err
	}
	return s.Users.AddRequiredActionTx(ctx, tx, userID, identity.ActionConfigureTOTP)
}

// RevokeConsentTx revokes a user's consent to a client and ends the client's
// grants for that user (APP-013). It returns the client reference.
func (s *Service) RevokeConsentTx(ctx context.Context, tx pgx.Tx, realmID, userID, consentID string) (string, error) {
	var clientRef string
	if err := tx.QueryRow(ctx, `UPDATE consents SET revoked_at=$3 WHERE id=$1 AND user_id=$2 AND realm_id=$4 AND revoked_at IS NULL RETURNING client_ref`,
		consentID, userID, s.d.Now(), realmID).Scan(&clientRef); err != nil {
		return "", problem.ErrNotFound
	}
	rows, err := tx.Query(ctx, `SELECT id FROM authorization_grants WHERE subject_id=$1 AND client_ref=$2 AND state='active'`, userID, clientRef)
	if err != nil {
		return "", err
	}
	var grants []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			rows.Close()
			return "", err
		}
		grants = append(grants, g)
	}
	rows.Close()
	for _, g := range grants {
		if err := s.Sessions.RevokeGrantTx(ctx, tx, g, "consent_revoked"); err != nil {
			return "", err
		}
	}
	return clientRef, nil
}
