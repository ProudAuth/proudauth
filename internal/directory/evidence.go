package directory

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
)

// endpointHealth is what a node observed of one endpoint.
type endpointHealth struct {
	LastOKAt        *time.Time `json:"last_ok_at,omitempty"`
	LastFailureAt   *time.Time `json:"last_failure_at,omitempty"`
	LastFailure     string     `json:"last_failure_category,omitempty"`
	ConsecutiveFail int        `json:"consecutive_failures"`
	persisted       string
}

// recordHealth notes an endpoint outcome ("" is success). A change of an
// endpoint's status is persisted on the connector, so every node and the
// health API see it; repeated identical outcomes stay in memory only.
func (s *Service) recordHealth(c *Connector, endpoint, category string) {
	now := s.d.Now()
	key := c.ID + "|" + endpoint
	s.healthMu.Lock()
	h := s.health[key]
	if h == nil {
		h = &endpointHealth{}
		s.health[key] = h
	}
	status := "ok"
	if category == "" {
		h.LastOKAt, h.ConsecutiveFail = &now, 0
	} else {
		h.LastFailureAt, h.LastFailure, status = &now, category, category
		h.ConsecutiveFail++
	}
	changed := status != h.persisted
	h.persisted = status
	snapshot := *h
	s.healthMu.Unlock()
	if !changed || s.d.DB == nil {
		return
	}
	b, _ := json.Marshal(snapshot)
	_, _ = s.d.DB.Pool.Exec(context.Background(), `UPDATE provisioning_connectors SET evidence = jsonb_set(evidence, ARRAY['endpoints', $2::text], $3::jsonb, true)
		WHERE id=$1 AND evidence ? 'endpoints'`, c.ID, hostOf(endpoint), b)
	_, _ = s.d.DB.Pool.Exec(context.Background(), `UPDATE provisioning_connectors SET evidence = evidence || jsonb_build_object('endpoints', jsonb_build_object($2::text, $3::jsonb))
		WHERE id=$1 AND NOT evidence ? 'endpoints'`, c.ID, hostOf(endpoint), b)
}

// Health is a connector's operational evidence (PROV-018). It never
// contains credentials or directory data beyond host names.
type Health struct {
	ConnectorID string `json:"connector_id"`
	Kind        string `json:"kind"`
	State       string `json:"state"`
	Status      string `json:"status"`
	// ConfigurationError says why an outbound connector cannot deliver
	// (status needs_configuration), for example a legacy row without a
	// destination.
	ConfigurationError  string                     `json:"configuration_error,omitempty"`
	CredentialSetAt     *time.Time                 `json:"credential_set_at,omitempty"`
	LastSyncAt          *time.Time                 `json:"last_sync_at,omitempty"`
	LastSuccessAt       *time.Time                 `json:"last_success_at,omitempty"`
	LagSeconds          *int64                     `json:"lag_seconds,omitempty"`
	ConsecutiveFailures int                        `json:"consecutive_failures"`
	LastError           string                     `json:"last_error,omitempty"`
	Endpoints           map[string]*endpointHealth `json:"endpoints,omitempty"`
	LastRun             *Run                       `json:"last_run,omitempty"`
	ManagedAccounts     map[string]int             `json:"managed_accounts,omitempty"`
	ManagedGroups       int                        `json:"managed_groups"`
	Deliveries          map[string]int             `json:"deliveries,omitempty"`
	OldestDueSeconds    int64                      `json:"oldest_due_seconds"`
	LastDeliveredAt     *time.Time                 `json:"last_delivered_at,omitempty"`
	OperatorActions     []any                      `json:"operator_actions"`
}

// Health reports a connector's operational evidence.
func (s *Service) Health(ctx context.Context, realmID, orgID, id string) (*Health, error) {
	c, err := s.Get(ctx, realmID, orgID, id)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	h := &Health{ConnectorID: c.ID, Kind: c.Kind, State: c.State, CredentialSetAt: c.CredentialSetAt, LastSyncAt: c.LastSyncAt,
		LastSuccessAt: c.LastSuccessAt, ConsecutiveFailures: c.ConsecutiveFailures, LastError: c.LastError, OperatorActions: []any{}}
	if c.LastSuccessAt != nil {
		lag := int64(now.Sub(*c.LastSuccessAt).Seconds())
		h.LagSeconds = &lag
	}
	if ops, ok := c.evidence["operator_actions"].([]any); ok {
		h.OperatorActions = ops
	}
	if eps, ok := c.evidence["endpoints"].(map[string]any); ok {
		h.Endpoints = map[string]*endpointHealth{}
		for host, v := range eps {
			b, _ := json.Marshal(v)
			var e endpointHealth
			_ = json.Unmarshal(b, &e)
			h.Endpoints[host] = &e
		}
	}
	if runs, err := s.Runs(ctx, realmID, orgID, id, 1); err == nil && len(runs) == 1 {
		h.LastRun = runs[0]
	}
	h.ManagedAccounts = map[string]int{}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT coalesce(source_state, CASE WHEN link_kind='outbound' AND snapshot_digest='deactivated' THEN 'deactivated'
		ELSE 'active' END), count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' GROUP BY 1`, c.ID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var st string
		var n int
		if rows.Scan(&st, &n) == nil {
			h.ManagedAccounts[st] = n
		}
	}
	rows.Close()
	_ = s.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM connector_external_ids WHERE connector_id=$1 AND resource_type='Group'`, c.ID).Scan(&h.ManagedGroups)
	if c.Kind == KindOutbound {
		h.Deliveries = map[string]int{"pending": 0, "retrying": 0, "delivered": 0, "dead_letter": 0}
		var oldest *time.Time
		rows, err := s.d.DB.Pool.Query(ctx, `SELECT state, count(*) FROM outbound_deliveries WHERE connector_id=$1 GROUP BY state`, c.ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var st string
			var n int
			if rows.Scan(&st, &n) == nil {
				h.Deliveries[st] = n
			}
		}
		rows.Close()
		_ = s.d.DB.Pool.QueryRow(ctx, `SELECT min(next_attempt_at) FILTER (WHERE state IN ('pending','retrying')), max(delivered_at)
			FROM outbound_deliveries WHERE connector_id=$1`, c.ID).Scan(&oldest, &h.LastDeliveredAt)
		if oldest != nil && oldest.Before(now) {
			h.OldestDueSeconds = int64(now.Sub(*oldest).Seconds())
		}
	}
	h.Status = "healthy"
	h.ConfigurationError = c.outboundConfigIssue()
	switch {
	case c.State != "active":
		h.Status = "disabled"
	case h.ConfigurationError != "":
		h.Status = "needs_configuration"
	case !c.CredentialSet:
		h.Status = "needs_credential"
	case c.ConsecutiveFailures > 0 || h.Deliveries["dead_letter"] > 0:
		h.Status = "degraded"
	}
	for _, e := range h.Endpoints {
		if e.ConsecutiveFail > 0 && h.Status == "healthy" {
			h.Status = "degraded"
		}
	}
	return h, nil
}

// TestResult is the outcome of a connection test.
type TestResult struct {
	OK        bool           `json:"ok"`
	Endpoint  string         `json:"endpoint,omitempty"`
	Error     string         `json:"error,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	CheckedAt time.Time      `json:"checked_at"`
}

// Test checks a connector's connectivity and credential without changing
// anything (operator action, PROV-018): a directory connector connects,
// negotiates TLS and binds as its service account; an outbound connector
// reads the downstream ServiceProviderConfig.
func (s *Service) Test(ctx context.Context, realmID, orgID, id string, actor audit.Ref) (*TestResult, error) {
	c, err := s.Get(ctx, realmID, orgID, id)
	if err != nil {
		return nil, err
	}
	res := &TestResult{CheckedAt: s.d.Now(), Details: map[string]any{}}
	switch c.Kind {
	case KindLDAP:
		err = s.withDirectory(ctx, c, true, func(cn *conn) error {
			res.Endpoint = hostOf(cn.endpoint)
			if state, ok := cn.l.TLSConnectionState(); ok {
				res.Details["tls_version"] = tlsVersion(state.Version)
			}
			server, _, _ := cn.rootDSE()
			res.Details["server"] = server
			return nil
		})
	case KindOutbound:
		var o outcome
		_, _, o, err = s.scimCall(ctx, c, "GET", "/ServiceProviderConfig", nil)
		res.Endpoint = hostOf(c.out.BaseURL)
		res.Details["status_code"] = o.status
		if err == nil && o.category != "" {
			res.Error = o.category
		}
	}
	if err != nil {
		res.Error = publicError(err)
	}
	res.OK = res.Error == ""
	terr := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.recordOperatorAction(ctx, tx, c, "tested", actor); err != nil {
			return err
		}
		outcome := audit.Success
		if !res.OK {
			outcome = audit.Failure
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.connector.tested", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: actor,
			Category: "operations", Target: &audit.Ref{Type: "connector", ID: c.ID}, Outcome: outcome, Metadata: map[string]any{"endpoint": res.Endpoint}})
		return err
	})
	return res, terr
}

func tlsVersion(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS1.3"
	case 0x0303:
		return "TLS1.2"
	}
	return "other"
}
