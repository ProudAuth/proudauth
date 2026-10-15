package e2e

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/provisioning"
	"github.com/proudauth/proudauth/internal/realm"
)

type scimQueryCounter struct{ calls atomic.Int64 }

func (c *scimQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.calls.Add(1)
	return ctx
}
func (*scimQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// TestSCIMListsBoundDatabaseRoundTrips covers PROV-002, PROV-008, NFR-004
// and NFR-006: growing a managed set must not add per-user database round
// trips. Trace real PostgreSQL queries rather than asserting a machine's
// speed; exact filtered totals and per-item data/ETags must still agree.
func TestSCIMListsBoundDatabaseRoundTrips(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	c := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{"name": "bounded-list-fixture", "role_ceiling_ids": []string{f.Roles["orders-viewer"]}, "default_role_id": f.Roles["orders-viewer"]}), 201, "connector")
	token := c.Str("token")
	connector, err := h.App.Provisioning.Authenticate(ctx, h.Realm.ID, token)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := provisioning.ParseFilter("(" + strings.TrimSuffix(strings.Repeat("active eq true or ", 32), " or ") + ")")
	if err != nil {
		t.Fatal(err)
	}
	old := h.App.D.DB.Pool
	cfg := old.Config()
	counter := &scimQueryCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.App.D.DB.Pool = pool
	t.Cleanup(func() { h.App.D.DB.Pool = old; pool.Close() })
	base := h.Base + "/api/v1/realms/main/scim/v2"
	created := 0
	for _, size := range []int{8, 64} {
		for created < size {
			r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/scim/v2/Users", Headers: map[string]string{"Authorization": "Bearer " + token}, JSON: map[string]any{"userName": fmt.Sprintf("bounded-list-%d", created), "externalId": fmt.Sprintf("external-%d", created), "active": created%2 == 0}})
			mustStatus(t, r, 201, "owned fixture")
			created++
		}
		counter.calls.Store(0)
		items, total, err := h.App.Provisioning.ListUsers(ctx, connector, filter, 1, 3, base)
		calls := counter.calls.Load()
		t.Logf("%d managed users: %d database round trips", size, calls)
		if err != nil {
			t.Fatal(err)
		}
		if total != size/2 || len(items) != 3 {
			t.Fatalf("size %d: total %d, page %d", size, total, len(items))
		}
		// A fixed small budget allows ordinary query refactors, but refuses
		// an N+1 path even on eight users, without flaky latency assertions.
		if calls > 8 {
			t.Errorf("%d managed users caused %d database round trips; require bounded work <=8", size, calls)
		}
		for _, item := range items {
			id, _ := item["id"].(string)
			single, _, err := h.App.Provisioning.GetUser(ctx, connector, id, base)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(item, single) {
				t.Fatal("list changed managed data or ETag compared to single-resource read")
			}
		}
	}
}

// DOM-002, DOM-007: the internal batch read retains realm qualification,
// identifier order and all User fields even when foreign/missing IDs are
// mixed into the request. Empty and over-limit input fail without widening it.
func TestUserBatchReadsKeepRealmAndIdentifierOrder(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	id := f.Users["alice"]
	other, err := h.App.Provision.CreateRealm(ctx, "batch-other", "Batch other", realm.DefaultPolicy(), audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var foreign *identity.User
	if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		foreign, err = h.App.Users.CreateTx(ctx, tx, other.ID, identity.CreateInput{Email: "alice@example.test", Username: "foreign-batch-user", State: identity.StateActive, DisplayName: "Foreign synthetic account"})
		if err != nil {
			return err
		}
		_, err = h.App.Users.AddIdentifierTx(ctx, tx, h.Realm.ID, id, "email", "batch-alias@example.test", false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want, err := h.App.Users.User(ctx, nil, h.Realm.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Identifiers) < 2 {
		t.Fatal("identifier order fixture is incomplete")
	}
	if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		got, err := h.App.Users.UsersByID(ctx, tx, h.Realm.ID, []string{id, foreign.ID, "missing-user", id})
		if err != nil {
			return err
		}
		if len(got) != 1 || !reflect.DeepEqual(got[id], want) {
			t.Error("batch widened realm scope or changed identifiers/user fields")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	empty, err := h.App.Users.UsersByID(ctx, nil, h.Realm.ID, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty batch %v %v", empty, err)
	}
	if _, err := h.App.Users.UsersByID(ctx, nil, h.Realm.ID, make([]string, 20001)); err == nil {
		t.Fatal("unbounded internal batch accepted")
	}
}
