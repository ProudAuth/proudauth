package directory

import "github.com/proudauth/proudauth/internal/observability"

// metrics are the module's operational signals (PROV-018). Labels are
// bounded enumerations: connector IDs, hosts and users never become label
// values.
type metrics struct {
	binds     *observability.Counter
	failovers *observability.Counter
	runs      *observability.Counter
	changes   *observability.Counter
	outbound  *observability.Counter
	lag       *observability.Gauge
	backlog   *observability.Gauge
}

func newMetrics(r *observability.Registry) *metrics {
	return &metrics{
		binds: r.Counter("proudauth_directory_binds_total",
			"Directory sign-in binds by outcome (success, invalid_credentials, unavailable, disabled)", "outcome"),
		failovers: r.Counter("proudauth_directory_failovers_total",
			"Directory endpoint failures that moved an operation to the next configured endpoint, by category (PROV-014)", "category"),
		runs: r.Counter("proudauth_directory_sync_runs_total",
			"Directory synchronization and outbound reconciliation runs by mode and final state (PROV-012, PROV-017)", "mode", "state"),
		changes: r.Counter("proudauth_directory_sync_changes_total",
			"Records changed or reported by directory runs, by finding kind (created, updated, deprovisioned, conflict, ...)", "kind"),
		outbound: r.Counter("proudauth_outbound_provisioning_total",
			"Outbound SCIM provisioning attempts by operation and outcome (PROV-010); updated by identity-worker", "operation", "outcome"),
		lag: r.Gauge("proudauth_directory_sync_lag_seconds",
			"Seconds since the least recently successful synchronization of an active scheduled directory connector (PROV-018)", nil),
		backlog: r.Gauge("proudauth_outbound_provisioning_backlog",
			"Open outbound provisioning deliveries (pending or retrying) across connectors (PROV-018)", nil),
	}
}
