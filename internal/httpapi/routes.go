package httpapi

import (
	"net/http"
)

func (a *App) routes(mux *http.ServeMux) {
	// Public metadata (trust class: public metadata).
	mux.HandleFunc("GET /realms/{realm}/.well-known/openid-configuration", a.public(a.discovery))
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/realms/{realm}", a.rfc8414)
	mux.HandleFunc("GET /realms/{realm}/jwks", a.public(a.jwks))
	// Protocol endpoints.
	mux.HandleFunc("GET /realms/{realm}/oauth/authorize", a.public(a.authorize))
	mux.HandleFunc("POST /realms/{realm}/oauth/authorize", a.public(a.authorize))
	mux.HandleFunc("POST /realms/{realm}/oauth/token", a.public(a.tokenEndpoint))
	mux.HandleFunc("POST /realms/{realm}/oauth/introspect", a.public(a.introspect))
	mux.HandleFunc("POST /realms/{realm}/oauth/revoke", a.public(a.revoke))
	mux.HandleFunc("POST /realms/{realm}/oauth/device_authorization", a.public(a.deviceAuthorization))
	mux.HandleFunc("POST /realms/{realm}/oauth/par", a.public(a.par))
	mux.HandleFunc("GET /realms/{realm}/oidc/userinfo", a.public(a.userinfo))
	mux.HandleFunc("POST /realms/{realm}/oidc/userinfo", a.public(a.userinfo))
	mux.HandleFunc("GET /realms/{realm}/oidc/check-session", a.public(a.checkSessionIframe))
	mux.HandleFunc("GET /realms/{realm}/oidc/check-session/origin", a.public(a.checkSessionOrigin))
	mux.HandleFunc("GET /realms/{realm}/oidc/logout", a.public(a.logout))
	mux.HandleFunc("POST /realms/{realm}/oidc/logout", a.public(a.logout))
	mux.HandleFunc("GET /realms/{realm}/oidc/logout/upstream-return", a.public(a.logoutUpstreamReturn))
	// CORS preflight for registered origins.
	mux.HandleFunc("OPTIONS /realms/{realm}/", a.preflight)
	mux.HandleFunc("OPTIONS /api/v1/realms/{realm}/", a.preflight)
	// Interaction, self-service, tenant and administration APIs.
	a.transactionRoutes(mux)
	a.selfRoutes(mux)
	a.tenantRoutes(mux)
	a.adminRoutes(mux)
	a.adminIdentifierRoutes(mux)
	a.opsRoutes(mux)
	a.federationRoutes(mux)
	a.policyRoutes(mux)
	a.sessionEventRoutes(mux)
	a.hookRoutes(mux)
	a.activityRoutes(mux)
	a.orgIdentityProviderRoutes(mux)
	a.messagingRoutes(mux)
	a.extraRoutes(mux)
	a.emergencyRoutes(mux)
	a.lifecycleRoutes(mux)
	a.externalIDRoutes(mux)
	a.consentRoutes(mux)
	a.templateRoutes(mux)
	a.legalHoldRoutes(mux)
	a.workloadRoutes(mux)
	a.dcrRoutes(mux)
	a.relationRoutes(mux)
	a.elevationRoutes(mux)
	a.flowRevisionRoutes(mux)
	a.ssfRoutes(mux)
	a.webauthnTrustRoutes(mux)
	a.federationTransferRoutes(mux)
	a.orgRelationshipRoutes(mux)
	a.registryRoutes(mux)
	a.investigationRoutes(mux)
	a.ssfReceiverRoutes(mux)
	a.reviewRoutes(mux)
	a.certificateRoutes(mux)
	a.reportedActivityRoutes(mux)
	a.importedAuditRoutes(mux)
	a.migrationRoutes(mux)
	a.privacyRoutes(mux)
	a.customDomainRoutes(mux)
	a.scimRoutes(mux)
	a.extensibilityRoutes(mux)
	a.samlRoutes(mux)
	a.directoryRoutes(mux)
	// Health.
	mux.HandleFunc("GET /health/live", a.live)
	mux.HandleFunc("GET /health/ready", a.Ready)
}

// extraRoutes is extended by optional modules.
func (a *App) extraRoutes(mux *http.ServeMux) {
	for _, fn := range a.extensions {
		fn(mux)
	}
}
