package contracts

import (
	"encoding/json"
	"fmt"
)

// RenderEvent renders a stored envelope (always version 1 in the outbox) in
// the event schema version a subscription chose (EXT-008, EXT-018). form is
// the subscription's payload form ("minimal" or "standard"), already applied
// to data by the caller.
//
// Version 1 is returned byte for byte: subscriptions created before event
// versioning keep exactly what they received before the upgrade.
//
// Version 2 changes the envelope only, so per-type data shapes are the same
// in both versions:
//   - org_id is renamed organization_id, the name every data member, the
//     session change stream and the REST API use;
//   - payload_form states which payload form data is in, so consumers can
//     tell "member absent" from "member stripped by the minimal form";
//   - event_version is 2.
func RenderEvent(envelope []byte, version int, form string) ([]byte, error) {
	switch version {
	case 0, 1:
		return envelope, nil
	case 2:
		var m map[string]any
		if err := json.Unmarshal(envelope, &m); err != nil {
			return nil, err
		}
		if org, ok := m["org_id"]; ok {
			delete(m, "org_id")
			m["organization_id"] = org
		}
		m["event_version"] = 2
		if form != "minimal" && form != "standard" {
			form = "minimal"
		}
		m["payload_form"] = form
		return json.Marshal(m)
	}
	return nil, fmt.Errorf("contracts: unsupported event version %d", version)
}
