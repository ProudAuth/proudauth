package httpapi

import (
	"encoding/json"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// writeList renders a bounded, ordered list one page at a time with a stable
// opaque cursor (API-004). The cursor is HMAC-bound to the realm, the route
// and the request's filters, so it cannot be replayed against another tenant,
// route or filter set; page sizes are capped by limits.max_page_size. The
// cursor names the last item returned (its "id"), so pages stay stable when
// earlier items are inserted or removed.
func (a *App) writeList(w http.ResponseWriter, r *http.Request, items any) error {
	v := reflect.ValueOf(items)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	n := 0
	if v.IsValid() && v.Kind() == reflect.Slice {
		n = v.Len()
	}
	scope := listScope(r)
	after, err := a.decodeCursor(scope, r.URL.Query().Get("cursor"))
	if err != nil {
		return err
	}
	start := 0
	if after != "" {
		id, offset, _ := strings.Cut(after, "@")
		start = -1
		for i := 0; i < n; i++ {
			if itemID(v.Index(i).Interface()) == id {
				start = i + 1
				break
			}
		}
		if start < 0 {
			// The anchor item is gone; resume at its former position.
			start, _ = strconv.Atoi(offset)
		}
	}
	start = min(max(start, 0), n)
	end := min(start+a.pageLimit(r), n)
	page := make([]any, 0, end-start)
	for i := start; i < end; i++ {
		page = append(page, v.Index(i).Interface())
	}
	next := ""
	if end < n && end > start {
		next = a.encodeCursor(scope, itemID(page[len(page)-1])+"@"+strconv.Itoa(end))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": page, "next_cursor": next})
	return nil
}

// listScope binds a cursor to the realm, route pattern and filter parameters.
func listScope(r *http.Request) string {
	q := url.Values{}
	for k, vs := range r.URL.Query() {
		if k != "cursor" && k != "limit" {
			q[k] = vs
		}
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + strings.Join(q[k], ",") + "&")
	}
	return "list|" + r.PathValue("realm") + "|" + r.Pattern + "|" + b.String()
}

// itemID extracts an item's "id" member for cursor anchoring.
func itemID(item any) string {
	if m, ok := item.(map[string]any); ok {
		s, _ := m["id"].(string)
		return s
	}
	b, err := json.Marshal(item)
	if err != nil {
		return ""
	}
	var m struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &m)
	return m.ID
}

// keyset is a position in a list ordered newest first by (time, id), for
// lists paged in the database rather than in memory (API-004).
type keyset struct {
	At time.Time
	ID string
}

// pageAfter decodes the request's cursor into a keyset position (nil on the
// first page). The cursor is bound like writeList's.
func (a *App) pageAfter(r *http.Request) (*keyset, error) {
	raw, err := a.decodeCursor(listScope(r), r.URL.Query().Get("cursor"))
	if err != nil || raw == "" {
		return nil, err
	}
	ns, id, ok := strings.Cut(strings.TrimPrefix(raw, "k|"), "|")
	n, perr := strconv.ParseInt(ns, 10, 64)
	if !ok || perr != nil || !strings.HasPrefix(raw, "k|") {
		return nil, problem.ErrValidation.WithField("cursor", "invalid cursor")
	}
	return &keyset{At: time.Unix(0, n).UTC(), ID: id}, nil
}

// writePage renders a database-paged list; next is the position of the last
// item when more items follow.
func (a *App) writePage(w http.ResponseWriter, r *http.Request, items any, next *keyset) {
	cur := ""
	if next != nil {
		cur = a.encodeCursor(listScope(r), "k|"+strconv.FormatInt(next.At.UnixNano(), 10)+"|"+next.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": cur})
}
