package server

import "github.com/proudauth/proudauth/internal/httpapi"

// RegisterModules wires optional modules (policies, webhooks, federation,
// passkeys, SCIM, ...) into the application. Each module registers only the routes
// and discovery capabilities it fully implements (APP-020).
func RegisterModules(app *httpapi.App) {
	for _, m := range modules {
		m(app)
	}
}

var modules []func(*httpapi.App)

// Register adds a module initializer.
func Register(fn func(*httpapi.App)) { modules = append(modules, fn) }
