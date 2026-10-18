package session

import "testing"

// TestSenderBindingRefusal covers the sender check of refresh rotation
// (TOK-019, owner decision 13): a family bound to a DPoP key or a TLS client
// certificate is satisfied only by a request that proves the same one, a
// missing proof is refused like a wrong one, and an unbound family (issued
// without a sender constraint or before migration 0089) accepts any
// request.
func TestSenderBindingRefusal(t *testing.T) {
	const jkt, other = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	cases := []struct {
		name      string
		bound     SenderBinding
		proof     SenderBinding
		kind, why string
	}{
		{"unbound, no proof", SenderBinding{}, SenderBinding{}, "", ""},
		{"unbound, any proof", SenderBinding{}, SenderBinding{JKT: jkt, X5TS256: other}, "", ""},
		{"DPoP, same key", SenderBinding{JKT: jkt}, SenderBinding{JKT: jkt}, "", ""},
		{"DPoP, same key and a certificate", SenderBinding{JKT: jkt}, SenderBinding{JKT: jkt, X5TS256: other}, "", ""},
		{"DPoP, no proof", SenderBinding{JKT: jkt}, SenderBinding{}, "dpop", "missing"},
		{"DPoP, certificate only", SenderBinding{JKT: jkt}, SenderBinding{X5TS256: jkt}, "dpop", "missing"},
		{"DPoP, another key", SenderBinding{JKT: jkt}, SenderBinding{JKT: other}, "dpop", "mismatch"},
		{"mTLS, same certificate", SenderBinding{X5TS256: jkt}, SenderBinding{X5TS256: jkt}, "", ""},
		{"mTLS, same certificate and a DPoP proof", SenderBinding{X5TS256: jkt}, SenderBinding{JKT: other, X5TS256: jkt}, "", ""},
		{"mTLS, no certificate", SenderBinding{X5TS256: jkt}, SenderBinding{}, "mtls", "missing"},
		{"mTLS, DPoP proof only", SenderBinding{X5TS256: jkt}, SenderBinding{JKT: jkt}, "mtls", "missing"},
		{"mTLS, another certificate", SenderBinding{X5TS256: jkt}, SenderBinding{X5TS256: other}, "mtls", "mismatch"},
		{"thumbprints compare exactly", SenderBinding{JKT: jkt}, SenderBinding{JKT: jkt + " "}, "dpop", "mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, why := tc.bound.refusal(tc.proof)
			if kind != tc.kind || why != tc.why {
				t.Fatalf("refusal = %q, %q; want %q, %q", kind, why, tc.kind, tc.why)
			}
		})
	}
}
