package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/hooks"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/token"
)

// DecisionRequest is the §15.3 request.
type DecisionRequest struct {
	SubjectToken string `json:"subject_token"`
	Subject      *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"subject"`
	Action   string `json:"action"`
	Resource struct {
		Type  string `json:"type"`
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
		// ProjectID names the project the resource belongs to (AZ-002): the
		// subject's project-scoped roles for that project are evaluated too.
		// The project must exist in the realm and, with an organization,
		// belong to it (owned, or shared through an active project grant).
		ProjectID string `json:"project_id,omitempty"`
	} `json:"resource"`
	Context map[string]any `json:"context"`
	// SubjectAttributes describe a hypothetical session of an explicitly named
	// subject. They are accepted only by simulation (requires
	// realm.authorization.simulate) and ignored when a subject token is supplied.
	SubjectAttributes *struct {
		ACR            string `json:"acr"`
		AuthAgeSeconds int    `json:"auth_age_seconds"`
		ClientID       string `json:"client_id"`
		OrgID          string `json:"org_id"`
	} `json:"subject_attributes,omitempty"`
}

// Decision is the §15.3 response. Obligations are mandatory conditions: a caller that
// cannot enforce them must deny.
type Decision struct {
	DecisionID    string           `json:"decision_id"`
	Allowed       bool             `json:"allowed"`
	ReasonCode    string           `json:"reason_code"`
	PolicyVersion string           `json:"policy_version"`
	Obligations   []map[string]any `json:"obligations"`
	// CacheTTLSeconds and CacheKey are the cache contract (AZ-019): callers
	// may reuse the decision for at most CacheTTLSeconds and only for requests
	// with the same CacheKey. The key covers realm, subject, actor, client,
	// organization, resource (with its project and that project's state),
	// action, the subject's authorization revision,
	// the policy version and the asserted context, so a role, policy or
	// membership change yields a different key. 0 means do not cache.
	CacheTTLSeconds int    `json:"cache_ttl_seconds"`
	CacheKey        string `json:"cache_key,omitempty"`
}

// cacheHint makes a pure RBAC decision cacheable (AZ-019). Decisions that
// depend on time, freshness or external input (ABAC policies, step-up,
// hooks, support access, privileged actions, conditional, scheduled or
// rule-derived grants) are never cacheable. The key covers the request, the
// token evidence (kind, audience, assurance) and a fingerprint of every
// assignment, role version, membership and organization state the decision
// rests on, so any change to them yields a different key.
func (a *App) cacheHint(ctx context.Context, p *Principal, req DecisionRequest, sc *subjectContext, orgID string, d *Decision) {
	ttl := a.D.Cfg.Security.DecisionCacheTTL
	if ttl <= 0 || len(d.Obligations) > 0 || sc.kind == token.KindImpersonationAccess {
		return
	}
	var rev int64
	if sc.subject.Type == authorization.SubjectUser {
		_ = a.D.DB.Pool.QueryRow(ctx, `SELECT authz_revision FROM users WHERE id=$1`, sc.subject.ID).Scan(&rev)
	} else {
		_ = a.D.DB.Pool.QueryRow(ctx, `SELECT permission_revision FROM service_principals WHERE id=$1`, sc.subject.ID).Scan(&rev)
	}
	// The assignments that apply: direct ones and those of the subject's
	// groups and their ancestors, with the versions of their roles and of
	// every role those compose; time-dependent ones forbid caching, as do
	// group memberships with a validity window.
	var fingerprint string
	var timeDependent bool
	err := a.D.DB.Pool.QueryRow(ctx, `WITH RECURSIVE mygroups(id, depth) AS (
			SELECT gm.group_id, 0 FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id WHERE m.user_id=$3 AND m.state='active'
			UNION SELECT g.parent_id, d.depth+1 FROM groups g JOIN mygroups d ON g.id=d.id WHERE g.parent_id IS NOT NULL AND d.depth < 64),
		ap AS (SELECT ra.id, ra.role_id, ra.conditions, ra.valid_from, ra.expires_at FROM role_assignments ra
			WHERE ra.realm_id=$1 AND ((ra.subject_type=$2 AND ra.subject_id=$3) OR (ra.subject_type='group' AND ra.subject_id IN (SELECT id FROM mygroups)))),
		closure(aid, rid) AS (SELECT id, role_id FROM ap
			UNION SELECT c.aid, x.id FROM closure c JOIN roles r ON r.realm_id=$1 AND r.id=c.rid CROSS JOIN LATERAL unnest(r.composite_role_ids) AS x(id))
		SELECT coalesce((SELECT md5(string_agg(c.aid || ':' || c.rid || ':' || ro.version, ',' ORDER BY c.aid, c.rid))
				FROM closure c JOIN roles ro ON ro.realm_id=$1 AND ro.id=c.rid), ''),
			EXISTS (SELECT 1 FROM ap WHERE conditions <> '{}'::jsonb OR (valid_from IS NOT NULL AND valid_from > now())
				OR (expires_at IS NOT NULL AND expires_at < now() + $4::interval))
			OR EXISTS (SELECT 1 FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id WHERE m.user_id=$3
				AND (gm.source='dynamic' OR gm.valid_from IS NOT NULL OR gm.valid_until IS NOT NULL))`,
		p.Realm.ID, sc.subject.Type, sc.subject.ID, fmt.Sprintf("%d seconds", int(ttl.Seconds()))).Scan(&fingerprint, &timeDependent)
	if err != nil || timeDependent {
		return
	}
	var orgState string
	if orgID != "" {
		_ = a.D.DB.Pool.QueryRow(ctx, `SELECT o.state || ':' || o.authz_revision || ':' || coalesce((SELECT m.state || ':' || m.revision FROM memberships m
			WHERE m.organization_id=o.id AND m.user_id=$2 ORDER BY m.created_at DESC LIMIT 1), '-') FROM organizations o WHERE o.id=$1`,
			orgID, sc.subject.ID).Scan(&orgState)
	}
	// A project's roles count while it is active and belongs to the
	// organization (owner or an active grant): those are part of the key.
	var projectState string
	if pid := req.Resource.ProjectID; pid != "" {
		if err := a.D.DB.Pool.QueryRow(ctx, `SELECT p.state || ':' || coalesce(p.owner_organization_id,'') || ':' || p.version || ':' ||
			coalesce((SELECT string_agg(g.id || ':' || g.state || ':' || coalesce(g.valid_until::text,''), ',' ORDER BY g.id)
				FROM project_grants g WHERE g.project_id=p.id AND g.organization_id=$3), '')
			FROM projects p WHERE p.realm_id=$1 AND p.id=$2`, p.Realm.ID, pid, orgID).Scan(&projectState); err != nil {
			return
		}
	}
	asserted, _ := json.Marshal(req.Context)
	h := sha256.New()
	for _, part := range []string{p.Realm.ID, sc.subject.Type, sc.subject.ID, sc.actor, sc.clientID, sc.audience, sc.kind, sc.acr, orgID,
		req.Resource.Type, req.Resource.ID, req.Resource.ProjectID, req.Action, strconv.FormatInt(rev, 10), fingerprint, orgState, projectState,
		d.PolicyVersion, string(asserted)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	d.CacheKey = hex.EncodeToString(h.Sum(nil))
	d.CacheTTLSeconds = int(ttl.Seconds())
}

type subjectContext struct {
	clientID    string
	audience    string
	subject     authorization.Subject
	orgID       string
	kind        string
	authTime    time.Time
	acr         string
	actor       string
	supportMode string
	grantID     string
	// actorChain is the subject token's whole delegation chain (outermost
	// first) and agent marks a token whose subject is an agent; both are
	// audit evidence only (AUD-005).
	actorChain          []map[string]any
	actorChainTruncated bool
	agent               bool
}

func (a *App) authorizationCheck(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req DecisionRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if !a.can(r.Context(), p, "realm.authorization.check", a.realmScope(p)) {
		return problem.ErrForbidden
	}
	d := a.decide(r.Context(), p, req)
	writeJSON(w, http.StatusOK, d)
	return nil
}

func (a *App) authorizationCheckBatch(w http.ResponseWriter, r *http.Request, p *Principal) error {
	var req struct {
		Checks []DecisionRequest `json:"checks"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	if !a.can(r.Context(), p, "realm.authorization.check", a.realmScope(p)) {
		return problem.ErrForbidden
	}
	if len(req.Checks) == 0 || len(req.Checks) > a.D.Cfg.Limits.MaxBatchSize {
		return problem.ErrValidation.WithField("checks", "1..max_batch_size checks")
	}
	out := make([]Decision, 0, len(req.Checks))
	for _, c := range req.Checks {
		out = append(out, a.decide(r.Context(), p, c)) // identical semantics per item (AZ-014)
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": out})
	return nil
}

// resolveSubject validates the subject. A free-form subject ID is accepted only for
// callers allowed to evaluate arbitrary subjects (§15.3).
func (a *App) resolveSubject(ctx context.Context, p *Principal, req DecisionRequest) (*subjectContext, string) {
	if req.SubjectToken != "" {
		rlm := p.Realm
		var claims map[string]any
		var err error
		if strings.HasPrefix(req.SubjectToken, "pa_") {
			// Opaque tokens (including support tokens) are resolved through introspection rules.
			claims, err = a.introspectForCaller(ctx, p, req.SubjectToken)
		} else {
			claims, err = a.introspectForCaller(ctx, p, req.SubjectToken)
		}
		if err != nil || claims["active"] != true {
			return nil, "SUBJECT_TOKEN_INACTIVE"
		}
		sc := &subjectContext{kind: str(claims["token_kind"]), orgID: str(claims["org_id"]), acr: str(claims["acr"])}
		sub := str(claims["sub"])
		if sc.kind == token.KindServiceAccess {
			sc.subject = authorization.Subject{Type: authorization.SubjectService, ID: sub}
		} else {
			sc.subject = authorization.Subject{Type: authorization.SubjectUser, ID: sub}
		}
		if at, ok := claims["auth_time"].(int64); ok {
			sc.authTime = time.Unix(at, 0)
		} else if at, ok := claims["auth_time"].(float64); ok {
			sc.authTime = time.Unix(int64(at), 0)
		}
		// Introspection returns the act claim of a JWT as a *token.Actor and
		// that of an opaque token as a JSON object; both are read, and the
		// whole chain is kept for the audit record (AUD-005).
		if act := token.ActorFrom(claims["act"]); act != nil {
			sc.actor = act.Subject
			sc.actorChain, sc.actorChainTruncated = act.AuditChain()
		}
		sc.agent = claims["agent"] == true
		sc.supportMode = str(claims["support_mode"])
		sc.grantID = str(claims["impersonation_grant_id"])
		sc.clientID = str(claims["client_id"])
		sc.audience = str(claims["aud"])
		_ = rlm
		return sc, ""
	}
	if req.Subject != nil && req.Subject.ID != "" {
		if !a.can(ctx, p, "realm.authorization.simulate", a.realmScope(p)) {
			return nil, "SUBJECT_EVALUATION_NOT_PERMITTED"
		}
		typ := req.Subject.Type
		if typ == "" {
			typ = authorization.SubjectUser
		}
		sc := &subjectContext{subject: authorization.Subject{Type: typ, ID: req.Subject.ID}, kind: "evaluation"}
		if sa := req.SubjectAttributes; sa != nil {
			// Session evidence (assurance, authentication age, client) can be
			// asserted only for what-if simulation. A real decision about a named
			// subject has no session evidence, so MFA or freshness conditions fail
			// closed rather than trusting the caller (AZ-016).
			if sim, _ := ctx.Value(simulationKey{}).(bool); !sim {
				return nil, "SUBJECT_ATTRIBUTES_SIMULATION_ONLY"
			}
			sc.acr, sc.clientID, sc.orgID = sa.ACR, sa.ClientID, sa.OrgID
			if sa.AuthAgeSeconds > 0 {
				sc.authTime = a.D.Now().Add(-time.Duration(sa.AuthAgeSeconds) * time.Second)
			}
		}
		return sc, ""
	}
	return nil, "SUBJECT_REQUIRED"
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// projectParam validates the optional project_id query parameter of the
// permission inspection views (AZ-002, AZ-009), as the decision API
// validates resource.project_id: the project must exist in the realm and,
// with an organization, belong to it.
func (a *App) projectParam(r *http.Request, p *Principal, orgID string) (string, error) {
	pid := r.URL.Query().Get("project_id")
	if pid == "" {
		return "", nil
	}
	exists, belongs, err := a.Authz.ProjectContext(r.Context(), nil, p.Realm.ID, pid, orgID)
	if err != nil {
		return "", err
	}
	if !exists || !belongs {
		return "", problem.ErrValidation.WithField("project_id", "unknown project, or not part of the organization")
	}
	return pid, nil
}

// introspectForCaller applies introspection authority: the calling service must be a
// registered resource server for the token's audience.
func (a *App) introspectForCaller(ctx context.Context, p *Principal, raw string) (map[string]any, error) {
	if p.Kind != "service_principal" {
		return nil, problem.ErrForbidden
	}
	var clientRef string
	if err := a.D.DB.Pool.QueryRow(ctx, `SELECT id FROM clients WHERE realm_id=$1 AND client_id=$2`, p.Realm.ID, p.ClientID).Scan(&clientRef); err != nil {
		return nil, err
	}
	allowed, err := a.Apps.IntrospectableResources(ctx, clientRef)
	if err != nil {
		return nil, err
	}
	return a.OAuth.IntrospectWithAllowed(ctx, p.Realm, raw, allowed), nil
}

var readOnlySuffixes = []string{".read", ".list", ".view", ".get", ".search"}

func (a *App) decide(ctx context.Context, p *Principal, req DecisionRequest) Decision {
	return a.decideWith(ctx, p, req, nil, true)
}

type simulationKey struct{}

// policyOverride replaces (or adds) one policy revision during simulation.
type policyOverride struct {
	policyID string
	label    string
	scope    string
	scopeID  string
	def      *authorization.PolicyDefinition
}

// decideWith evaluates a decision. With an override, the candidate revision is
// evaluated instead of the policy's active one, and nothing is audited (AZ-017
// simulation).
func (a *App) decideWith(ctx context.Context, p *Principal, req DecisionRequest, override *policyOverride, record bool) Decision {
	if !record {
		// Simulations are not audited as real decisions; the flag travels with
		// this call only.
		ctx = context.WithValue(ctx, simulationKey{}, true)
	}
	d := Decision{DecisionID: ids.New(ids.Decision), PolicyVersion: "realm-policy-" + itoa64(p.Realm.PolicyRevision), Obligations: []map[string]any{}}
	// Denials keep the subject, actor and support grant once the subject is
	// resolved, so refusals are evidence like grants are (AZ-020, IMP-006).
	var sc *subjectContext
	deny := func(code string) Decision {
		d.Allowed = false
		d.ReasonCode = code
		a.recordDecision(ctx, p, req, d, sc)
		return d
	}
	// Deny by default on any missing or malformed input (AZ-007).
	if req.Action == "" || len(req.Action) > 128 || req.Resource.Type == "" {
		return deny("INVALID_REQUEST")
	}
	sc, code := a.resolveSubject(ctx, p, req)
	if sc == nil {
		return deny(code)
	}
	orgID := req.Resource.OrgID
	if sc.orgID != "" && orgID != "" && sc.orgID != orgID {
		return deny("ORGANIZATION_MISMATCH") // TEST-007/008
	}
	if orgID == "" {
		orgID = sc.orgID
	}
	// A named project is validated, never trusted: it must exist in the
	// realm and belong to the decision's organization (AZ-002, AZ-007).
	if pid := req.Resource.ProjectID; pid != "" {
		if len(pid) > 128 {
			return deny("INVALID_REQUEST")
		}
		exists, belongs, err := a.Authz.ProjectContext(ctx, nil, p.Realm.ID, pid, orgID)
		switch {
		case err != nil:
			return deny("EVALUATION_ERROR")
		case !exists:
			return deny("UNKNOWN_PROJECT")
		case !belongs:
			return deny("PROJECT_ORGANIZATION_MISMATCH")
		}
	}
	if sc.kind == token.KindImpersonationAccess {
		// Support access: protected identity actions are always denied, and read-only
		// mode excludes state-changing actions (IMP-011, IMP-012, IMP-013).
		if authorization.IsSupportForbidden(req.Action) {
			return deny("SUPPORT_ACCESS_FORBIDDEN_ACTION")
		}
		read := slices.ContainsFunc(readOnlySuffixes, func(s string) bool { return strings.HasSuffix(strings.ToLower(req.Action), s) }) &&
			!authorization.IsWriteAction(req.Action)
		if !read {
			if sc.supportMode != "allowlisted_write" {
				return deny("SUPPORT_ACCESS_READ_ONLY")
			}
			// Writes need the resource's reviewed allowlist (IMP-011).
			res, err := a.Apps.ResourceByAudience(ctx, nil, p.Realm.ID, sc.audience)
			if err != nil || !slices.ContainsFunc(res.ImpersonationPolicy.WriteActions, func(w string) bool { return strings.EqualFold(strings.TrimSpace(w), req.Action) }) {
				return deny("SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED")
			}
		}
	}
	scope := authorization.Scope{Type: authorization.ScopeRealm, ID: p.Realm.ID}
	if orgID != "" {
		scope = orgScope(orgID)
	}
	// Conditional grants are evaluated against the subject token's context, not
	// the calling service's (AZ-012, AZ-016).
	dctx := authorization.WithDecisionContext(ctx, authorization.DecisionContext{ClientID: sc.clientID, ACR: sc.acr, AuthTime: sc.authTime,
		Resources: []string{sc.audience}})
	// A resource of a project is also governed by the subject's roles in
	// that project, and only there (AZ-002).
	ps, err := a.Authz.EffectiveInProject(dctx, nil, p.Realm.ID, sc.subject, scope, req.Resource.ProjectID)
	if err != nil {
		return deny("EVALUATION_ERROR")
	}
	relational := false
	engineConsulted, engineAllowed := false, false
	var engineObligations []map[string]any
	if !ps.Has(req.Action) {
		// Object-level grants through relationships (AZ-021): only for a
		// named object inside the decision's organization. Such decisions
		// depend on tuples the cache key does not cover, so they are never
		// cacheable.
		viaRelation := false
		if _, terr := a.Authz.ResourceTypeByName(ctx, nil, p.Realm.ID, req.Resource.Type); terr == nil && req.Resource.ID != "" && orgID != "" {
			relational = true
			ok, err := a.Authz.CheckObject(ctx, nil, p.Realm.ID, orgID, sc.subject, req.Resource.Type, req.Resource.ID, req.Action)
			if err != nil && !errors.Is(err, authorization.ErrRelationBound) {
				return deny("EVALUATION_ERROR")
			}
			viaRelation = ok
		}
		if !viaRelation {
			// In decide mode an external engine may allow what local rules do
			// not (AZ-026); later restrictions still apply.
			if pe := p.Realm.Policy.PolicyEngine; pe.Name != "" && pe.Mode == "decide" {
				engineConsulted = true
				v, cfg, err := a.consultEngine(ctx, p, req, sc, orgID, false, "NOT_PERMITTED")
				switch {
				case err != nil && pe.OnError == "local":
				case err != nil:
					a.D.Log.Warn("policy engine unavailable", "engine", pe.Name, "error", err)
					return deny("EXTERNAL_POLICY_UNAVAILABLE")
				case v.Allowed:
					engineAllowed = true
					d.PolicyVersion += ";engine:" + cfg.Name + ":" + v.PolicyVersion
					engineObligations = v.Obligations
				default:
					d.PolicyVersion += ";engine:" + cfg.Name + ":" + v.PolicyVersion
					return deny(firstNonEmptyStr(v.ReasonCode, "EXTERNAL_POLICY_DENIED"))
				}
			}
			if !engineAllowed {
				d.Allowed, d.ReasonCode = false, "NOT_PERMITTED"
				if !relational && p.Realm.Policy.PolicyEngine.Name == "" {
					a.cacheHint(ctx, p, req, sc, orgID, &d)
				}
				a.recordDecision(ctx, p, req, d, sc)
				return d
			}
		}
	}
	// Privileged actions need fresh multi-factor authentication (obligation).
	var sensitivity string
	_ = a.D.DB.Pool.QueryRow(ctx, `SELECT sensitivity FROM permissions WHERE realm_id=$1 AND name=$2`, p.Realm.ID, req.Action).Scan(&sensitivity)
	if sensitivity == "privileged" && sc.subject.Type == authorization.SubjectUser {
		fresh := !sc.authTime.IsZero() && a.D.Now().Sub(sc.authTime) <= 5*time.Minute
		strong := strings.HasSuffix(sc.acr, ":mfa") || strings.HasSuffix(sc.acr, ":phishing_resistant")
		if !fresh || !strong {
			d.Allowed = false
			d.ReasonCode = "STEP_UP_REQUIRED"
			d.Obligations = []map[string]any{{"type": "reauthenticate", "required_profile": "mfa", "max_age_seconds": 300}}
			a.recordDecision(ctx, p, req, d, sc)
			return d
		}
	}
	// Published ABAC policies restrict the RBAC result (AZ-013, AZ-015).
	policies, err := a.Authz.ActivePolicies(ctx, p.Realm.ID)
	if err != nil {
		return deny("EVALUATION_ERROR")
	}
	if override != nil {
		kept := policies[:0:0]
		for _, ap := range policies {
			if ap.ID != override.policyID {
				kept = append(kept, ap)
			}
		}
		policies = append(kept, &authorization.ActivePolicy{ID: override.policyID, Name: override.label, ScopeType: override.scope,
			ScopeID: override.scopeID, Definition: override.def})
	}
	in := a.policyInput(req, sc, orgID, ps)
	labels := []string{d.PolicyVersion}
	var obligations []authorization.Obligation
	for _, ap := range policies {
		if ap.ScopeType == authorization.ScopeOrganization && ap.ScopeID != orgID {
			continue
		}
		res := ap.Definition.Evaluate(in)
		if !res.Applicable {
			continue
		}
		label := ap.Label()
		if override != nil && ap.ID == override.policyID {
			label = override.label
		}
		labels = append(labels, label)
		if res.Denied {
			d.Allowed = false
			d.ReasonCode = res.ReasonCode
			d.PolicyVersion = strings.Join(labels, ";")
			d.Obligations = authorization.ObligationMaps(res.Obligations)
			a.recordDecision(ctx, p, req, d, sc)
			return d
		}
		obligations = append(obligations, res.Obligations...)
	}
	d.PolicyVersion = strings.Join(labels, ";")
	if a.PolicyEval != nil {
		if pd := a.PolicyEval(ctx, p.Realm.ID, sc.subject, req, sc.authTime, sc.acr); pd != nil {
			if pd.PolicyVersion != "" {
				d.PolicyVersion += ";" + pd.PolicyVersion
			}
			if !pd.Allowed {
				d.Allowed = false
				d.ReasonCode = pd.ReasonCode
				d.Obligations = pd.Obligations
				a.recordDecision(ctx, p, req, d, sc)
				return d
			}
		}
	}
	// A realm's external engine has its say once local rules allow (restrict
	// mode, or decide mode when it was not asked yet) (AZ-026).
	if pe := p.Realm.Policy.PolicyEngine; pe.Name != "" && !engineConsulted {
		v, cfg, err := a.consultEngine(ctx, p, req, sc, orgID, true, "ALLOWED")
		switch {
		case err != nil && pe.OnError == "local":
		case err != nil:
			a.D.Log.Warn("policy engine unavailable", "engine", pe.Name, "error", err)
			return deny("EXTERNAL_POLICY_UNAVAILABLE")
		case !v.Allowed:
			d.PolicyVersion += ";engine:" + cfg.Name + ":" + v.PolicyVersion
			d.Obligations = v.Obligations
			if d.Obligations == nil {
				d.Obligations = []map[string]any{}
			}
			return deny(firstNonEmptyStr(v.ReasonCode, "EXTERNAL_POLICY_DENIED"))
		default:
			d.PolicyVersion += ";engine:" + cfg.Name + ":" + v.PolicyVersion
			engineObligations = v.Obligations
		}
	}
	// Remaining obligations (approval, justification) must be enforced by the
	// caller, which must deny if it cannot (§15.3).
	d.Obligations = append(authorization.ObligationMaps(obligations), engineObligations...)
	// Authorization hooks run last; they can deny or add obligations, never
	// grant, and an unreachable hook denies (EXT-011, EXT-012).
	if a.Hooks != nil {
		ok, reason, extra := a.Hooks.Authorize(ctx, p.Realm.ID, sc.clientID, hooks.AuthzInput{Subject: in.Subject, Action: req.Action, Resource: in.Resource, Context: in.Context})
		if !ok {
			d.Allowed = false
			d.ReasonCode = reason
			a.recordDecision(ctx, p, req, d, sc)
			return d
		}
		d.Obligations = append(d.Obligations, extra...)
	}
	d.Allowed = true
	d.ReasonCode = "ALLOWED"
	if sensitivity != "privileged" && !relational && p.Realm.Policy.PolicyEngine.Name == "" && len(labels) == 1 && (a.PolicyEval == nil) && !a.hooksActive(ctx, p.Realm.ID) {
		a.cacheHint(ctx, p, req, sc, orgID, &d)
	}
	if sensitivity == "privileged" || sc.kind == token.KindImpersonationAccess {
		a.recordDecision(ctx, p, req, d, sc)
	} else if pct := p.Realm.Policy.DataAccess.SampleAllowedDecisionsPercent; pct > 0 && mrand.IntN(100) < pct {
		// Optional sampling of ordinary allows (AZ-020), marked as sampled.
		a.recordDecision(context.WithValue(ctx, sampledKey{}, true), p, req, d, sc)
	}
	return d
}

// policyInput builds the trusted evaluation input (AZ-016): subject attributes
// from the validated token and the IdP's own records, resource and context
// attributes as asserted by the authenticated calling service, environment from
// the IdP clock.
func (a *App) policyInput(req DecisionRequest, sc *subjectContext, orgID string, ps *authorization.PermissionSet) *authorization.PolicyInput {
	now := a.D.Now()
	assurance := "single_factor"
	switch {
	case strings.HasSuffix(sc.acr, ":phishing_resistant"):
		assurance = "phishing_resistant"
	case strings.HasSuffix(sc.acr, ":mfa"):
		assurance = "mfa"
	case strings.HasSuffix(sc.acr, ":federated"):
		assurance = "federated"
	case strings.HasSuffix(sc.acr, ":recovery"):
		assurance = "recovery"
	}
	roles := make([]any, 0, len(ps.RoleNames))
	for _, r := range ps.RoleNames {
		roles = append(roles, r)
	}
	subject := map[string]any{"id": sc.subject.ID, "type": sc.subject.Type, "assurance": assurance, "acr": sc.acr,
		"is_support": sc.kind == token.KindImpersonationAccess, "roles": roles, "org_id": orgID}
	if sc.clientID != "" {
		subject["client_id"] = sc.clientID
	}
	if sc.actor != "" {
		subject["actor_id"] = sc.actor
	}
	if !sc.authTime.IsZero() {
		subject["auth_age_seconds"] = now.Sub(sc.authTime).Seconds()
	}
	resource := map[string]any{"type": req.Resource.Type}
	if req.Resource.ID != "" {
		resource["id"] = req.Resource.ID
	}
	if org := firstNonEmptyStr(req.Resource.OrgID, orgID); org != "" {
		resource["org_id"] = org
	}
	if req.Resource.ProjectID != "" {
		resource["project_id"] = req.Resource.ProjectID // validated by decideWith
	}
	ctxAttrs := map[string]any{}
	for k, v := range req.Context {
		if len(ctxAttrs) >= 50 || len(k) > 64 {
			break
		}
		ctxAttrs[k] = v
	}
	env := map[string]any{"now_unix": float64(now.Unix()), "hour_utc": float64(now.UTC().Hour()), "weekday": float64(now.UTC().Weekday())}
	return &authorization.PolicyInput{Action: req.Action, Subject: subject, Resource: resource, Context: ctxAttrs, Environment: env,
		ACR: sc.acr, AuthTime: sc.authTime, Now: now}
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

type sampledKey struct{}

func (a *App) hooksActive(ctx context.Context, realmID string) bool {
	return a.Hooks != nil && a.Hooks.HasActive(ctx, realmID)
}

// recordDecision audits privileged decisions and denials with bounded context (AZ-020).
func (a *App) recordDecision(ctx context.Context, p *Principal, req DecisionRequest, d Decision, sc *subjectContext) {
	if sim, _ := ctx.Value(simulationKey{}).(bool); sim {
		return
	}
	ev := audit.Event{Type: "authorization.decision", RealmID: p.Realm.ID, OrgID: req.Resource.OrgID, Actor: p.AuditRef(), Category: "authorization",
		Outcome: map[bool]string{true: audit.Success, false: audit.Denied}[d.Allowed], ReasonCode: d.ReasonCode,
		Metadata: map[string]any{"decision_id": d.DecisionID, "action": req.Action, "resource_type": req.Resource.Type, "resource_id": req.Resource.ID}}
	if sampled, _ := ctx.Value(sampledKey{}).(bool); sampled {
		ev.Metadata["sampled"] = true
	}
	if req.Resource.ProjectID != "" {
		ev.Metadata["project_id"] = req.Resource.ProjectID
	}
	if sc != nil {
		ev.Subject = &audit.Ref{Type: sc.subject.Type, ID: sc.subject.ID}
		if sc.actor != "" {
			ev.Metadata["actor"] = sc.actor
		}
		// The whole delegation chain, not only its outermost actor (AUD-005).
		if len(sc.actorChain) > 0 {
			ev.Metadata["actor_chain"] = sc.actorChain
			if sc.actorChainTruncated {
				ev.Metadata["actor_chain_truncated"] = true
			}
		}
		if sc.agent {
			ev.Metadata["subject_agent"] = true
		}
		// Support decisions are tied to their grant for evidence queries (IMP-024).
		ev.ImpersonationGrantID = sc.grantID
	}
	_, _ = a.D.Audit.Record(ctx, a.D.DB.Pool, ev)
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
