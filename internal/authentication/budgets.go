package authentication

import (
	"context"
	"slices"
	"time"

	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/storage"
)

// Network-normalized abuse budgets and the known-device quota (owner decision
// 9 of 0.2.0-alpha.6; SEC-006, ABU-001, REG-012, TEN-018).
//
// Per-network budgets count the IPv4 /32 or IPv6 /64 of the request that makes
// a step, and a wider IPv4 /24 or IPv6 /48 budget at network_coarse_factor
// times the limit (ratelimit.PerNetwork), so neither rotating addresses inside
// one network nor starting each transaction from a fresh address escapes them.
// Starting a transaction is budgeted per network too (startBudget).
//
// The aggregate budgets that everyone using one client, organization or realm
// shares (password and proof attempts) used to be the last line once the
// per-network ones were evaded, and failed hard for everyone: an attacker who
// exhausted them blocked every password sign-in through the client or realm,
// window after window. They still fail closed for unknown requesters, but a
// sign-in from a network, a remembered device or an identifier that completed
// a sign-in in the last known_quota_days days proceeds under a separate quota
// of its own (hitBudgets). No CAPTCHA, no proof-of-work.

// Kinds of known_sign_ins facts.
const (
	knownNetwork    = "network"
	knownDevice     = "device"
	knownIdentifier = "identifier"
)

// knownRefresh is how stale a fact's last_seen_at may get before a sign-in
// refreshes it, so busy networks do not rewrite their row on every sign-in.
const knownRefresh = time.Hour

// chargeIP is the address a step's budgets are charged to: the address of the
// request that makes the step, so rotating addresses inside one transaction
// gains nothing, or the address the transaction started from when the call
// carries no request context.
func chargeIP(ctx context.Context, t *Transaction) string {
	if ip := reqctx.From(ctx).ClientIP; ip != "" {
		return ip
	}
	return t.ClientIP
}

// requester is who an attempt comes from, as far as the known-device quota is
// concerned.
type requester struct {
	ip         string // the request's address
	device     string // the remembered-device secret the request presented
	identifier string // the canonical identifier being signed in
}

// requesterOf describes the request making a step of t.
func requesterOf(ctx context.Context, t *Transaction) requester {
	return requester{ip: chargeIP(ctx, t), device: t.deviceToken, identifier: t.Pending.Identifier}
}

// hitBudgets consumes an attempt's budgets in one statement (SEC-006): its own
// budgets first (per identifier, account and network, the wider network
// included), then the aggregate ones it shares with everyone using the same
// client, organization or realm. Every budget is consumed, as in
// ratelimit.Limiter.Hit. When the first exhausted budget is an aggregate one,
// so none of the attempt's own budgets is, an attempt from a known network,
// remembered device or identifier proceeds under the known-device quota
// (knownQuota). Every other refusal is 429 rate_limited with Retry-After.
func (s *Service) hitBudgets(ctx context.Context, realmID string, who requester, own, shared []ratelimit.Budget) error {
	d, err := s.Limiter.Hit(ctx, append(slices.Clip(own), shared...)...)
	if err != nil {
		return err
	}
	if d.Allowed {
		return nil
	}
	limited := problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	if !slices.ContainsFunc(shared, func(b ratelimit.Budget) bool { return b.Key == d.Bucket }) {
		return limited
	}
	kd, known, err := s.knownQuota(ctx, realmID, who)
	switch {
	case err != nil:
		return err
	case !known:
		return limited
	case !kd.Allowed:
		return problem.ErrRateLimited.WithRetryAfter(kd.RetryAfter)
	}
	return nil
}

// knownQuota charges an attempt to the known-device quota. It finds the most
// specific fact the requester has, seen within known_quota_days: a remembered
// device that is still valid, then its network, then its identifier from the
// same wider network, skipping kinds whose limit is 0. The attempt is charged
// to that fact's own budget per login_window. known is false when the quota
// is off or the requester has no such fact. The facts are read only here, on
// the exhausted path, in one statement that looks each one up by primary key.
//
// An identifier is known only together with the wider network (IPv4 /24,
// IPv6 /48) it signed in from. Anyone can name an identifier: were it enough
// on its own, whoever exhausts an aggregate budget could tell the identifiers
// that signed in recently (admitted, then 401) from all others (429), and so
// which accounts exist (SEC-005, API-009). Bound to the wider network, only a
// requester inside the network the account used learns that, while a user
// whose address changed inside it (a new /64 from the same /48, a new IPv4
// address in the same /24) is still known.
func (s *Service) knownQuota(ctx context.Context, realmID string, who requester) (ratelimit.Decision, bool, error) {
	rl := s.d.Cfg.Security.RateLimits
	if rl.KnownQuotaDays <= 0 {
		return ratelimit.Decision{}, false, nil
	}
	limits := map[string]int{knownDevice: rl.KnownLoginPerDevice, knownNetwork: rl.KnownLoginPerNetwork, knownIdentifier: rl.KnownLoginPerIdentifier}
	values := map[string]string{}
	if who.device != "" && limits[knownDevice] > 0 && validDeviceToken(who.device) {
		values[knownDevice] = s.knownDigest(realmID, knownDevice, who.device)
	}
	if net := ratelimit.NetworkKey(who.ip); net != "" && limits[knownNetwork] > 0 {
		values[knownNetwork] = s.knownDigest(realmID, knownNetwork, net)
	}
	if wide := ratelimit.CoarseNetworkKey(who.ip); who.identifier != "" && wide != "" && limits[knownIdentifier] > 0 {
		values[knownIdentifier] = s.knownDigest(realmID, knownIdentifier, who.identifier, wide)
	}
	if values[knownDevice] == "" && values[knownNetwork] == "" && values[knownIdentifier] == "" {
		return ratelimit.Decision{}, false, nil
	}
	now := s.d.Now()
	// A digest that is "" matches no row: every stored digest is a keyed MAC.
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT kind FROM known_sign_ins k WHERE realm_id=$1 AND last_seen_at >= $2 AND (
			(kind='device' AND digest=$3 AND EXISTS (SELECT 1 FROM remembered_devices d WHERE d.realm_id=$1 AND d.token_digest=$6
				AND d.revoked_at IS NULL AND d.expires_at > $7))
			OR (kind='network' AND digest=$4) OR (kind='identifier' AND digest=$5))`,
		realmID, now.AddDate(0, 0, -rl.KnownQuotaDays), values[knownDevice], values[knownNetwork], values[knownIdentifier],
		secret.Digest(who.device), now)
	if err != nil {
		return ratelimit.Decision{}, false, err
	}
	found := map[string]bool{}
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			rows.Close()
			return ratelimit.Decision{}, false, err
		}
		found[kind] = true
	}
	if err := rows.Err(); err != nil {
		return ratelimit.Decision{}, false, err
	}
	for _, kind := range []string{knownDevice, knownNetwork, knownIdentifier} {
		if !found[kind] {
			continue
		}
		d, err := s.Limiter.Hit(ctx, ratelimit.Budget{Key: "known-" + kind + ":" + realmID + ":" + values[kind], Limit: limits[kind], Window: rl.LoginWindow})
		return d, true, err
	}
	return ratelimit.Decision{}, false, nil
}

// validDeviceToken reports whether a presented remembered-device secret has
// the form of one.
func validDeviceToken(token string) bool {
	return secret.HasPrefix(token, secret.PrefixRemember) && len(token) <= 128
}

// knownDigest is the stored form of a fact: a keyed digest, so the table holds
// no address, device secret or identifier, and a guessable address or
// identifier cannot be confirmed by hashing candidates (PRV-002). A rotated
// lookup key makes earlier facts unknown until the next sign-in.
func (s *Service) knownDigest(realmID, kind string, values ...string) string {
	mac, _ := s.d.Keys.MAC(keys.PurposeLookup, append([]string{"known-sign-in", realmID, kind}, values...)...)
	return mac
}

// knownFact is something a completed sign-in makes known.
type knownFact struct{ kind, digest string }

// knownFactsOf lists the facts of a sign-in that is completing: the network
// of the completing request, the remembered device it presented when that is
// valid for the account, a device remembered by this sign-in, and the
// identifier it signed in with together with the request's wider network
// (knownQuota says why). They are recorded after the sign-in commits
// (recordKnown).
func (s *Service) knownFactsOf(ctx context.Context, q storage.Querier, t *Transaction, newDevice string) []knownFact {
	if s.d.Cfg.Security.RateLimits.KnownQuotaDays <= 0 {
		return nil
	}
	var facts []knownFact
	add := func(kind string, values ...string) {
		if slices.Contains(values, "") {
			return
		}
		if d := s.knownDigest(t.RealmID, kind, values...); d != "" && !slices.Contains(facts, knownFact{kind, d}) {
			facts = append(facts, knownFact{kind, d})
		}
	}
	ip := chargeIP(ctx, t)
	if ip != "" {
		add(knownNetwork, ratelimit.NetworkKey(ip))
	}
	if t.deviceToken != "" && validDeviceToken(t.deviceToken) && s.rememberedDevice(ctx, q, t.RealmID, t.UserID, t.deviceToken) != "" {
		add(knownDevice, t.deviceToken)
	}
	add(knownDevice, newDevice)
	add(knownIdentifier, t.Pending.Identifier, ratelimit.CoarseNetworkKey(ip))
	return facts
}

// recordKnown stores the facts of a completed sign-in. It runs after the
// sign-in committed, in its own short statement, so a busy network's row is
// never locked for the length of a sign-in; a row is refreshed at most once
// per knownRefresh. A failure only leaves the facts unrecorded, which fails
// closed: the requester is not known when the aggregate budgets run out.
func (s *Service) recordKnown(ctx context.Context, realmID string, facts []knownFact) {
	if len(facts) == 0 {
		return
	}
	kinds, digests := make([]string, len(facts)), make([]string, len(facts))
	for i, f := range facts {
		kinds[i], digests[i] = f.kind, f.digest
	}
	now := s.d.Now()
	if _, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO known_sign_ins (realm_id, kind, digest, last_seen_at)
		SELECT $1, f.kind, f.digest, $4 FROM unnest($2::text[], $3::text[]) AS f(kind, digest) ORDER BY f.kind, f.digest
		ON CONFLICT (realm_id, kind, digest) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
		WHERE known_sign_ins.last_seen_at < $5`, realmID, kinds, digests, now, now.Add(-knownRefresh)); err != nil && s.d.Log != nil {
		s.d.Log.Warn("known sign-in facts not recorded", "component", "authentication", "event_code", "authentication.known_sign_in.failed",
			"realm_id", realmID, "error", err)
	}
}

// CleanupKnownSignIns deletes known-device quota facts older than
// security.rate_limits.known_quota_days, all of them when the quota is off
// (PRV-004).
func (s *Service) CleanupKnownSignIns(ctx context.Context) (int64, error) {
	days := s.d.Cfg.Security.RateLimits.KnownQuotaDays
	if days <= 0 {
		tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM known_sign_ins`)
		return tag.RowsAffected(), err
	}
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM known_sign_ins WHERE last_seen_at < $1`, s.d.Now().AddDate(0, 0, -days))
	return tag.RowsAffected(), err
}

// startBudget bounds the authentication transactions one network starts per
// login_window (start_per_network, with its wider network), so a fresh
// transaction per attempt does not buy fresh budgets (SEC-006, ABU-001).
func (s *Service) startBudget(ctx context.Context, realmID, ip string) error {
	rl := s.d.Cfg.Security.RateLimits
	d, err := s.Limiter.Hit(ctx, ratelimit.PerNetwork("start-ip:"+realmID+":", ip, rl.StartPerNetwork, rl.LoginWindow, rl.NetworkCoarseFactor)...)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	return nil
}
