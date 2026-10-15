package realm

import (
	"context"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/storage"
)

// CustomDomain is a host on which a realm's endpoints may be served besides
// the public origin (DEP-014). It changes neither the issuer nor any subject:
// tokens keep the canonical issuer, cookies are per host, and passkeys work
// on it only when the realm's WebAuthn RP ID covers it.
type CustomDomain struct {
	ID                 string     `json:"id"`
	Host               string     `json:"host"`
	State              string     `json:"state"`
	ChallengeExpiresAt *time.Time `json:"challenge_expires_at,omitempty"`
	VerifiedAt         *time.Time `json:"verified_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	// PasskeysUsable reports whether the realm's WebAuthn RP ID is this host
	// or a parent of it, so passkeys registered for the realm work here.
	PasskeysUsable bool `json:"passkeys_usable"`
}

// CustomDomainChallenge is returned once when a domain is added.
type CustomDomainChallenge struct {
	Domain     CustomDomain `json:"domain"`
	RecordName string       `json:"dns_record_name"`
	RecordType string       `json:"dns_record_type"`
	Value      string       `json:"dns_record_value"`
}

// CustomDomainTXT resolves DNS TXT records; replaceable in tests.
var CustomDomainTXT = func(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func (s *Service) publicHost() string {
	if u, err := url.Parse(s.d.Cfg.Server.PublicOrigin); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// AddCustomDomain registers a host and issues a DNS TXT proof challenge.
func (s *Service) AddCustomDomain(ctx context.Context, rlm *Realm, raw string, actor audit.Ref) (*CustomDomainChallenge, error) {
	host, err := canonical.Domain(raw)
	if err != nil || host == s.publicHost() {
		return nil, problem.ErrValidation.WithField("host", "a DNS name other than the public origin's host")
	}
	value := "proudauth-domain=" + secret.Token("")[:43]
	id := ids.New("cdm")
	now := s.d.Now()
	exp := now.Add(7 * 24 * time.Hour)
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO realm_custom_domains (id, realm_id, host, challenge_digest, challenge_expires_at, created_by_id, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, rlm.ID, host, secret.Digest(value), exp, actor.ID, now); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("host", "already registered in this realm")
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "realm.custom_domain.added", RealmID: rlm.ID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "custom_domain", ID: id}, Metadata: map[string]any{"host": host}})
		return err
	})
	if err != nil {
		return nil, err
	}
	d := CustomDomain{ID: id, Host: host, State: "pending", ChallengeExpiresAt: &exp, CreatedAt: now, PasskeysUsable: s.passkeysUsable(rlm, host)}
	return &CustomDomainChallenge{Domain: d, RecordName: "_proudauth-challenge." + host, RecordType: "TXT", Value: value}, nil
}

// VerifyCustomDomain checks the DNS proof; a verified host starts serving
// the realm under a strict host policy.
func (s *Service) VerifyCustomDomain(ctx context.Context, rlm *Realm, id string, actor audit.Ref) (*CustomDomain, error) {
	var d CustomDomain
	var digest *string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT id, host, state, challenge_digest, challenge_expires_at, verified_at, created_at FROM realm_custom_domains
		WHERE realm_id=$1 AND id=$2`, rlm.ID, id).Scan(&d.ID, &d.Host, &d.State, &digest, &d.ChallengeExpiresAt, &d.VerifiedAt, &d.CreatedAt)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	d.PasskeysUsable = s.passkeysUsable(rlm, d.Host)
	switch {
	case d.State == "verified":
		return &d, nil
	case d.State == "disabled":
		return nil, problem.ErrConflict.WithDetail("the domain was removed")
	case digest == nil || d.ChallengeExpiresAt == nil || !s.d.Now().Before(*d.ChallengeExpiresAt):
		return nil, problem.ErrConflict.WithDetail("challenge expired; remove and add the domain again")
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	records, _ := CustomDomainTXT(lctx, "_proudauth-challenge."+d.Host)
	matched := false
	for _, r := range records {
		if secret.Equal(secret.Digest(strings.TrimSpace(r)), *digest) {
			matched = true
		}
	}
	if !matched {
		return nil, problem.ErrValidation.WithDetail("the DNS TXT record was not found or does not match")
	}
	now := s.d.Now()
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// Only the pending challenge that was checked is verified: a removal
		// (or another verification) during the DNS lookup wins.
		tag, err := tx.Exec(ctx, `UPDATE realm_custom_domains SET state='verified', verified_at=$2, challenge_digest=NULL
			WHERE id=$1 AND state='pending' AND challenge_digest=$3`, d.ID, now, *digest)
		if err != nil {
			if storage.IsUniqueViolation(err) {
				// Another realm proved control of the host first.
				return problem.ErrConflict.WithField("host", "the host is already in use")
			}
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrConflict.WithDetail("the domain changed during verification; check its state")
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "realm.custom_domain.verified", RealmID: rlm.ID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "custom_domain", ID: d.ID}, Metadata: map[string]any{"host": d.Host}})
		return err
	})
	if err != nil {
		return nil, err
	}
	s.hosts.invalidate()
	d.State, d.VerifiedAt = "verified", &now
	return &d, nil
}

// RemoveCustomDomain stops serving the realm on a host.
func (s *Service) RemoveCustomDomain(ctx context.Context, realmID, id string, actor audit.Ref) error {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var host string
		if err := tx.QueryRow(ctx, `UPDATE realm_custom_domains SET state='disabled', disabled_at=$3, challenge_digest=NULL
			WHERE realm_id=$1 AND id=$2 AND state <> 'disabled' RETURNING host`, realmID, id, s.d.Now()).Scan(&host); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "realm.custom_domain.removed", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "custom_domain", ID: id}, Metadata: map[string]any{"host": host}})
		return err
	})
	if err == nil {
		s.hosts.invalidate()
	}
	return err
}

// CustomDomains lists a realm's hosts (removed ones excluded).
func (s *Service) CustomDomains(ctx context.Context, rlm *Realm) ([]CustomDomain, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, host, state, challenge_expires_at, verified_at, created_at FROM realm_custom_domains
		WHERE realm_id=$1 AND state <> 'disabled' ORDER BY host`, rlm.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CustomDomain{}
	for rows.Next() {
		var d CustomDomain
		if err := rows.Scan(&d.ID, &d.Host, &d.State, &d.ChallengeExpiresAt, &d.VerifiedAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.PasskeysUsable = s.passkeysUsable(rlm, d.Host)
		out = append(out, d)
	}
	return out, rows.Err()
}

// RealmForHost returns the realm ID a verified custom host serves, or "".
func (s *Service) RealmForHost(ctx context.Context, host string) string {
	return s.hosts.lookup(ctx, s.d.DB.Pool, strings.ToLower(host), s.d.Now())
}

// EffectiveRPID is the passkey relying-party ID the realm uses: the explicit
// policy value, otherwise the login UI's host, otherwise the issuer's host
// (the passkey module derives it the same way, PASS-008).
func (s *Service) EffectiveRPID(rlm *Realm) string {
	if rp := rlm.Policy.WebAuthn.RPID; rp != "" {
		return strings.ToLower(rp)
	}
	base := rlm.Policy.Interaction.LoginUIURL
	if base == "" {
		base = s.d.Cfg.Issuer(rlm.Name)
	}
	if u, err := url.Parse(base); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// passkeysUsable reports whether passkeys work on a custom host: the host
// must be the RP ID or a subdomain of it.
func (s *Service) passkeysUsable(rlm *Realm, host string) bool {
	rp := s.EffectiveRPID(rlm)
	return rp != "" && (host == rp || strings.HasSuffix(host, "."+rp))
}

// VerifiedHosts lists a realm's verified custom hosts.
func (s *Service) VerifiedHosts(ctx context.Context, realmID string) []string {
	return s.hosts.hostsOf(ctx, s.d.DB.Pool, realmID, s.d.Now())
}

// hostCache maps verified custom hosts to realm IDs, refreshed every 30 s
// and on every change made through this process.
type hostCache struct {
	mu      sync.Mutex
	loaded  time.Time
	byHost  map[string]string
	refresh bool
}

func (c *hostCache) invalidate() {
	c.mu.Lock()
	c.refresh = true
	c.mu.Unlock()
}

// ensure reloads the map when stale; c.mu must be held. A failed or partial
// read keeps the previous map and is retried on the next use.
func (c *hostCache) ensure(ctx context.Context, q storage.Querier, now time.Time) {
	if c.byHost != nil && !c.refresh && now.Sub(c.loaded) <= 30*time.Second {
		return
	}
	rows, err := q.Query(ctx, `SELECT host, realm_id FROM realm_custom_domains WHERE state='verified'`)
	if err != nil {
		return
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var h, r string
		if rows.Scan(&h, &r) != nil {
			return
		}
		m[h] = r
	}
	if rows.Err() != nil {
		return
	}
	c.byHost, c.loaded, c.refresh = m, now, false
}

func (c *hostCache) lookup(ctx context.Context, q storage.Querier, host string, now time.Time) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensure(ctx, q, now)
	return c.byHost[host]
}

func (c *hostCache) hostsOf(ctx context.Context, q storage.Querier, realmID string, now time.Time) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensure(ctx, q, now)
	var out []string
	for h, r := range c.byHost {
		if r == realmID {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}
