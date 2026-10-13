// Package contracts names the extension contracts ProudAuth versions
// independently of each other and of server releases (EXT-018, API-013):
//
//   - webhook event schemas (api/events/<type>.v<N>.json): each subscription
//     chooses the version its deliveries are rendered to;
//   - the pre-action hook request/response contract: each hook registration
//     pins the version it speaks, sent as the ProudAuth-Hook-Version header;
//   - the plugin manifest format (manifest_version);
//   - the lifecycle workflow definition schema (schema_version).
//
// A version stays supported for the support window after its successor is
// published (SupportWindow); a server upgrade inside the window never changes
// what an existing subscription, hook, plugin or workflow receives or must
// send. Compatibility tests render every supported version and check it
// against the published JSON schemas.
package contracts

import (
	"slices"
	"strconv"
	"strings"
)

// Contract names.
const (
	WebhookEvents      = "webhook_events"
	HookContract       = "hook_contract"
	PluginManifest     = "plugin_manifest"
	WorkflowDefinition = "workflow_definition"
	// WorkflowStepCall is the body a call_webhook step sends.
	WorkflowStepCall = "workflow_step_call"
	// ManagementAPI is the /api/v1 administration API major version; plugins
	// may require it like any other contract.
	ManagementAPI = "management_api"
)

// HookVersionHeader carries the hook contract version on every hook request.
// A hook may echo it in its response; an echoed version other than the one
// requested makes the response malformed, so the call fails as the hook's
// failure mode dictates (fail closed for security decisions, EXT-012).
const HookVersionHeader = "ProudAuth-Hook-Version"

// SupportWindowMonths is the minimum time a contract version stays supported
// after its successor is published. Deprecations are announced in the
// CHANGELOG and listed with a sunset date by GET /extension-contracts.
const SupportWindowMonths = 12

// Version describes one version of a contract.
type Version struct {
	Version int `json:"version"`
	// Status is "current" (the newest), "supported" or "deprecated" (still
	// served, with a sunset date no earlier than the support window).
	Status string `json:"status"`
	// Sunset is the earliest date (YYYY-MM-DD) the version may be removed;
	// empty while it has no successor.
	Sunset string `json:"sunset,omitempty"`
	// Default marks the version used when a caller does not choose one.
	Default bool `json:"default,omitempty"`
}

// Contract is one independently versioned extension contract.
type Contract struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Versions    []Version `json:"versions"`
}

// Registry lists every contract and the versions this server supports. The
// order of versions is oldest first.
var Registry = []Contract{
	{Name: WebhookEvents, Description: "Webhook event envelope and per-type payload schemas (api/events). Each subscription chooses event_version; deliveries are rendered to it.",
		Versions: []Version{{Version: 1, Status: "supported", Default: true}, {Version: 2, Status: "current"}}},
	{Name: HookContract, Description: "Pre-action hook request and response bodies (api/hooks). Each hook pins contract_version, sent as the ProudAuth-Hook-Version header.",
		Versions: []Version{{Version: 1, Status: "current", Default: true}}},
	{Name: PluginManifest, Description: "Signed plugin package manifest (api/plugins/manifest.v1.json).",
		Versions: []Version{{Version: 1, Status: "current", Default: true}}},
	{Name: WorkflowDefinition, Description: "Lifecycle workflow definition schema (api/workflows/definition.v1.json).",
		Versions: []Version{{Version: 1, Status: "current", Default: true}}},
	{Name: WorkflowStepCall, Description: "Body of the call a lifecycle workflow's call_webhook step sends (api/workflows/step-call.v1.json); contract_version in the body.",
		Versions: []Version{{Version: 1, Status: "current", Default: true}}},
	{Name: ManagementAPI, Description: "Administration API major version (/api/v1).",
		Versions: []Version{{Version: 1, Status: "current", Default: true}}},
}

// Lookup returns a contract by name.
func Lookup(name string) (Contract, bool) {
	for _, c := range Registry {
		if c.Name == name {
			return c, true
		}
	}
	return Contract{}, false
}

// Supported lists the versions of a contract this server serves.
func Supported(name string) []int {
	c, ok := Lookup(name)
	if !ok {
		return nil
	}
	out := make([]int, 0, len(c.Versions))
	for _, v := range c.Versions {
		out = append(out, v.Version)
	}
	return out
}

// IsSupported reports whether version v of a contract is served.
func IsSupported(name string, v int) bool { return slices.Contains(Supported(name), v) }

// Default returns the version used when a caller does not choose one. It
// stays the oldest supported version until that version's sunset, so clients
// written against it keep their behavior across server upgrades.
func Default(name string) int {
	c, _ := Lookup(name)
	for _, v := range c.Versions {
		if v.Default {
			return v.Version
		}
	}
	if len(c.Versions) > 0 {
		return c.Versions[0].Version
	}
	return 0
}

// Current returns the newest version of a contract.
func Current(name string) int {
	c, _ := Lookup(name)
	if len(c.Versions) == 0 {
		return 0
	}
	return c.Versions[len(c.Versions)-1].Version
}

// SupportedList renders a contract's versions for error messages ("1 or 2").
func SupportedList(name string) string {
	var parts []string
	for _, v := range Supported(name) {
		parts = append(parts, strconv.Itoa(v))
	}
	switch len(parts) {
	case 0:
		return "none"
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
}
