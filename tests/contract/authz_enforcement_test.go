package contract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// authenticatedWrappers are the App methods that authenticate a request
// (internal/httpapi/auth.go). They establish who the caller is, never what
// the caller may do: a.admin and a.tenant only add the token audience and,
// for a.admin, an MFA session.
var authenticatedWrappers = map[string]bool{"admin": true, "tenant": true, "self": true, "protected": true}

// permissionChecks are the calls that decide whether the authenticated
// caller may perform the request: the HTTP layer's helpers (all of them end
// in the RBAC engine) and the authorization service's check entry points.
var permissionChecks = map[string]bool{
	"a.can":         true, // auth.go: Authz.Check in a scope
	"a.requirePerm": true, // admin.go: realm permission, audits the denial
	"a.orgGuard":    true, // tenant.go: organization permission, conceals existence
	"a.dirScope":    true, // directory.go: realm or organization connector authority
	// authorization.Service (rbac.go, relations.go).
	"a.Authz.Check": true, "a.Authz.Require": true, "a.Authz.CheckAssignable": true, "a.Authz.CheckObject": true,
}

// serviceAuthorized are service operations that take the caller as the
// acting subject and decide its authority themselves, before changing
// anything; a route that calls one is authorized there. The value says
// where.
var serviceAuthorized = map[string]string{
	"a.Authz.CreateRole":              "rbac.go createRoleTx: realm.roles.write or org.roles.write and the delegation ceiling, composites included",
	"a.Authz.ModifyRolePermissions":   "rbac.go ModifyRolePermissionsTx: role write permission and the delegation ceiling",
	"a.Authz.DeleteRole":              "rbac.go DeleteRole: role write permission in the role's boundary",
	"a.Authz.Assign":                  "rbac.go AssignTx: CheckAssignable (assign permission and ceiling) for the actor",
	"a.Authz.Unassign":                "rbac.go UnassignTx: CheckAssignable for the actor",
	"a.Authz.RequestAssignment":       "approvals.go: CheckAssignable for the requester",
	"a.Authz.DecideAssignmentRequest": "approvals.go: CheckAssignable for the approver, requester re-checked",
	"a.Authz.CreateEligibility":       "elevation.go: CheckAssignable for the administrator",
	"a.Authz.DecideElevation":         "elevation.go: CheckAssignable for the approver",
	"a.Authz.OfferShare":              "shares.go: CheckObject on the shared object's share permission",
	"a.Imp.RequestAccess":             "impersonation.go checkActor: support.impersonation.start for the target's organization, MFA session",
	"a.Imp.Approve":                   "impersonation.go: support.impersonation.approve or org.support_access.approve (checkActor), or the customer",
	"a.Imp.Deny":                      "impersonation.go: the customer, the operator, or Authz.Check of the approving permission",
	"a.Imp.Issue":                     "impersonation.go: only the requesting operator, approved request re-validated",
	"a.Imp.Revoke":                    "impersonation.go: the operator, the customer, or support.impersonation.revoke",
	"a.Imp.CreateHandoff":             "impersonation.go: only the grant's operator",
}

// TestAuthenticatedRoutesCheckPermissions guards AZ-008 (backend
// enforcement): every route registered through an authenticating wrapper
// (a.admin, a.tenant, a.self, a.protected, directly or through a local
// helper such as guard or receiver) must reach a permission check
// (permissionChecks) or a service operation that authorizes the caller
// itself (serviceAuthorized), in its handler, the wrapper closure or the App
// methods it calls. Authentication alone, possession of an ID or UI
// visibility never authorizes. Routes whose authorization is decided
// otherwise are listed in authzExemptions with the reason; an exemption
// that is no longer needed, names an unregistered route, or (for
// self-service) names a route that is not registered through a.self fails
// the test, so a new route cannot silently skip the check and the list
// stays honest.
//
// The analysis is static and deliberately simple: it follows calls to App
// methods and to function literals bound in the registering function, up to
// a fixed depth, and looks for the calls named above.
func TestAuthenticatedRoutesCheckPermissions(t *testing.T) {
	registered := registeredRoutes(t)
	sc := newAuthzScanner(t)
	exempt := authzExemptions()
	authenticated := 0
	var missing []string
	checked := map[string]bool{}
	for r, pos := range registered {
		reg, ok := sc.registrations[pos]
		if !ok {
			t.Errorf("%s: registration at %s is not covered by the AZ-008 scanner (internal/httpapi only); extend it", r, pos)
			continue
		}
		res := sc.analyze(reg)
		if len(res.wrappers) == 0 {
			continue // public, protocol, SCIM and transaction-step routes authenticate otherwise
		}
		authenticated++
		key := r.String()
		if res.checked {
			checked[key] = true
			continue
		}
		e, ok := exempt[key]
		if !ok {
			missing = append(missing, key+" (registered at "+pos+")")
			continue
		}
		if e.selfOnly && (len(res.wrappers) != 1 || !res.wrappers["self"]) {
			t.Errorf("authzExemptions lists %s as self-service, but it is not registered through a.self", key)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("authenticated route performs no permission check (AZ-008); check the caller's permission, or add an exemption with its reason to authzExemptions: %s", m)
	}
	for key := range exempt {
		if checked[key] {
			t.Errorf("authzExemptions lists %s, which now performs a permission check; remove the exemption", key)
			continue
		}
		method, path, _ := strings.Cut(key, " ")
		if _, ok := registered[route{Method: strings.ToLower(method), Path: path}]; !ok {
			t.Errorf("authzExemptions lists %s, which is not a registered route", key)
		}
	}
	if authenticated < 100 {
		t.Fatalf("only %d authenticated routes found; the scanner is broken", authenticated)
	}
	t.Logf("%d authenticated routes, %d exempt", authenticated, len(exempt))
}

type authzExemption struct {
	reason   string
	selfOnly bool // must be registered through a.self
}

// authzExemptions lists the authenticated routes that perform no permission
// check of their own, with the reason their authorization is sound. Paths
// are relative to /api/v1/realms/{realm}.
func authzExemptions() map[string]authzExemption {
	out := map[string]authzExemption{}
	add := func(selfOnly bool, reason string, routes ...string) {
		for _, r := range routes {
			method, path, _ := strings.Cut(r, " ")
			out[method+" /api/v1/realms/{realm}"+path] = authzExemption{reason: reason, selfOnly: selfOnly}
		}
	}
	// a.self admits only a user's account-audience token (never a machine
	// or support token); these handlers act on p.SubjectID alone, so the
	// caller can reach only their own account.
	add(true, "self-service on the caller's own account, profile, credentials, sessions and data",
		"GET /me", "PATCH /me", "POST /me/upgrade", "POST /me/password",
		"GET /me/identifiers", "POST /me/identifiers", "DELETE /me/identifiers/{id}", "POST /me/identifiers/{id}/primary",
		"POST /verification-challenges", "POST /verification-challenges/{id}/consume",
		"GET /me/credentials", "DELETE /me/credentials/{id}", "GET /me/remembered-devices", "DELETE /me/remembered-devices",
		"DELETE /me/remembered-devices/{id}", "GET /me/webauthn", "PATCH /me/webauthn/{id}",
		"POST /me/webauthn/registration-options", "POST /me/webauthn/registration-complete",
		"POST /me/totp/enroll", "POST /me/totp/activate", "DELETE /me/totp",
		"POST /me/hotp/enroll", "POST /me/hotp/activate", "POST /me/hotp/resync", "DELETE /me/hotp",
		"POST /me/recovery-codes/regenerate", "GET /me/sessions", "DELETE /me/sessions/{id}", "POST /me/sessions/revoke-all",
		"GET /me/consents", "DELETE /me/consents/{id}", "GET /me/security-events", "GET /me/activity",
		"GET /me/linked-identities", "POST /me/linked-identities", "POST /me/linked-identities/confirm", "DELETE /me/linked-identities/{id}",
		"GET /me/notification-preferences", "PUT /me/notification-preferences", "GET /me/attribute-authority",
		"POST /me/exports", "POST /me/deletion-request", "DELETE /me/deletion-request",
		"GET /me/organizations", "GET /me/join-requests")
	// The effective-permission view evaluates the caller only; an
	// organization filter requires the caller's active membership (AZ-009).
	add(true, "the caller's own effective permissions", "GET /me/permissions")
	// Personal tokens are the caller's credentials; their scopes are capped
	// by the owner's current authority (Machine.ScopePolicy, MCH-006).
	add(true, "the caller's own personal tokens, capped by their authority",
		"GET /me/personal-tokens", "POST /me/personal-tokens", "DELETE /me/personal-tokens/{id}")
	// An organization switch re-runs the authorization request for the
	// caller's own client and membership (TEN-017).
	add(true, "organization switch for the caller's own client and membership", "POST /me/organization-grants")
	// Items addressed to the caller: the service matches the item's
	// addressee (or owner) to p.SubjectID and refuses otherwise.
	add(true, "an invitation addressed to the caller: the secret bound to the caller's verified identifier; acceptance re-checks the inviter's authority",
		"POST /invitations/accept", "POST /invitations/decline")
	add(true, "the caller's own join request; reviewers decide with org.join_requests.review",
		"POST /organizations/{org}/join-requests", "POST /organizations/{org}/join-requests/{id}/withdraw")
	add(true, "shares offered to or by the caller (accepting, declining, revoking their own)",
		"GET /me/shares", "POST /me/shares/{id}/accept", "POST /me/shares/{id}/decline", "DELETE /me/shares/{id}")
	add(true, "the caller's own elevations; eligibility was granted with CheckAssignable",
		"GET /me/elevation-eligibilities", "GET /me/elevations", "POST /me/elevations", "POST /me/elevations/{id}/end")
	add(true, "access-review items assigned to the caller as reviewer (never their own assignments)",
		"GET /me/access-reviews", "GET /me/access-reviews/{id}/items", "POST /me/access-reviews/{id}/items/{item}/decision")
	add(true, "workflow approvals naming the caller as approver",
		"GET /me/workflow-approvals", "POST /me/workflow-approvals/{id}/decision")
	add(true, "account merges and assisted recoveries of the caller's own account",
		"GET /me/account-merges", "POST /me/account-merges/{id}/confirm", "POST /me/account-merges/{id}/decline",
		"GET /me/assisted-recoveries", "POST /me/assisted-recoveries/{id}/cancel")
	add(true, "support access to the caller's own account (customer consent and revocation, IMP-*)",
		"GET /me/impersonation-requests", "GET /me/impersonation-grants", "PUT /me/support-access")
	return out
}

// ---------- scanner ----------

type authzRegistration struct {
	handler ast.Expr
	fn      *ast.FuncDecl
}

type authzScanner struct {
	fset          *token.FileSet
	methods       map[string]*ast.FuncDecl // App methods by name
	registrations map[string]authzRegistration
	bound         map[*ast.FuncDecl]map[string][]binding
}

func newAuthzScanner(t *testing.T) *authzScanner {
	t.Helper()
	sc := &authzScanner{fset: token.NewFileSet(), methods: map[string]*ast.FuncDecl{}, registrations: map[string]authzRegistration{},
		bound: map[*ast.FuncDecl]map[string][]binding{}}
	dir := filepath.Join(repoRoot, httpAPIDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(sc.fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if fd.Recv != nil && len(fd.Recv.List) == 1 && receiverIsApp(fd.Recv.List[0].Type) {
				sc.methods[fd.Name.Name] = fd
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if name := calleeName(call); (name == "HandleFunc" || name == "Handle") && len(call.Args) == 2 {
					sc.registrations[sc.fset.Position(call.Pos()).String()] = authzRegistration{handler: call.Args[1], fn: fd}
				}
				return true
			})
		}
	}
	if len(sc.methods) == 0 || len(sc.registrations) == 0 {
		t.Fatal("authorization scanner found no App methods or route registrations")
	}
	for name := range authenticatedWrappers {
		if sc.methods[name] == nil {
			t.Fatalf("authenticating wrapper a.%s no longer exists; update authenticatedWrappers", name)
		}
	}
	return sc
}

func receiverIsApp(x ast.Expr) bool {
	if st, ok := x.(*ast.StarExpr); ok {
		x = st.X
	}
	id, ok := x.(*ast.Ident)
	return ok && id.Name == "App"
}

type authzResult struct {
	wrappers map[string]bool
	checked  bool
}

// maxAuthzDepth bounds how many App method or closure hops are followed.
const maxAuthzDepth = 6

func (sc *authzScanner) analyze(reg authzRegistration) authzResult {
	res := authzResult{wrappers: map[string]bool{}}
	var start ast.Node = reg.handler
	if id, ok := reg.handler.(*ast.Ident); ok {
		// mux.HandleFunc(pattern, h) with h := a.admin(...) or a function literal.
		start = sc.localBinding(reg.fn, id.Name, id.Pos(), true)
	}
	sc.walk(start, reg.fn, &res, map[ast.Node]bool{}, 0)
	return res
}

// walk inspects n for wrapper and check calls, following App methods
// (calls and method values such as a.admin(a.authorizationCheck)) and
// function literals bound in fn, the function that registers the route,
// when they are called or passed as arguments (guard(...), receiver(...),
// a.admin(h)).
func (sc *authzScanner) walk(n ast.Node, fn *ast.FuncDecl, res *authzResult, seen map[ast.Node]bool, depth int) {
	if n == nil || seen[n] || depth > maxAuthzDepth {
		return
	}
	seen[n] = true
	closure := func(id *ast.Ident) {
		if fn != nil {
			sc.walk(sc.localBinding(fn, id.Name, id.Pos(), false), fn, res, seen, depth+1)
		}
	}
	ast.Inspect(n, func(x ast.Node) bool {
		switch v := x.(type) {
		case *ast.CallExpr:
			q := qualifiedName(v.Fun)
			if permissionChecks[q] || serviceAuthorized[q] != "" {
				res.checked = true
			}
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok && authenticatedWrappers[sel.Sel.Name] && isReceiverA(sel) {
				res.wrappers[sel.Sel.Name] = true
			}
			if id, ok := v.Fun.(*ast.Ident); ok {
				closure(id)
			}
			for _, arg := range v.Args {
				if id, ok := arg.(*ast.Ident); ok {
					closure(id)
				}
			}
		case *ast.SelectorExpr:
			if m, ok := sc.methods[v.Sel.Name]; ok && isReceiverA(v) && !authenticatedWrappers[v.Sel.Name] {
				sc.walk(m.Body, m, res, seen, depth+1)
			}
		}
		return true
	})
}

func isReceiverA(sel *ast.SelectorExpr) bool {
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "a"
}

// qualifiedName renders a selector chain such as a.Authz.Check.
func qualifiedName(x ast.Expr) string {
	switch v := x.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if q := qualifiedName(v.X); q != "" {
			return q + "." + v.Sel.Name
		}
	}
	return ""
}

// binding is one local single-value assignment (name := expr or
// name = expr) of a function literal or a call, visible within [from, to).
type binding struct {
	pos, from, to token.Pos
	expr          ast.Expr
}

// bindings indexes the bindings of fn by name, each with the lexical scope
// (innermost block, if, for, switch or case clause) it is visible in.
func (sc *authzScanner) bindings(fn *ast.FuncDecl) map[string][]binding {
	if b, ok := sc.bound[fn]; ok {
		return b
	}
	b := map[string][]binding{}
	var stack []ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
			var scope ast.Node = fn.Body
		outer:
			for i := len(stack) - 1; i >= 0; i-- {
				switch stack[i].(type) {
				case *ast.BlockStmt, *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt,
					*ast.CaseClause, *ast.CommClause, *ast.FuncLit:
					scope = stack[i]
					break outer
				}
			}
			for i, l := range as.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok {
					continue
				}
				switch as.Rhs[i].(type) {
				case *ast.FuncLit, *ast.CallExpr:
					b[id.Name] = append(b[id.Name], binding{pos: as.Pos(), from: scope.Pos(), to: scope.End(), expr: as.Rhs[i]})
				}
			}
		}
		stack = append(stack, n)
		return true
	})
	sc.bound[fn] = b
	return b
}

// localBinding returns the function literal (with calls, also a call) most
// recently bound to name in a scope enclosing use, or nil.
func (sc *authzScanner) localBinding(fn *ast.FuncDecl, name string, use token.Pos, calls bool) ast.Node {
	var best ast.Node
	var bestPos token.Pos
	for _, b := range sc.bindings(fn)[name] {
		if _, lit := b.expr.(*ast.FuncLit); !lit && !calls {
			continue
		}
		if b.pos < use && b.from <= use && use < b.to && b.pos > bestPos {
			best, bestPos = b.expr, b.pos
		}
	}
	return best
}
