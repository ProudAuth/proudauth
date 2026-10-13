package reqctx

import "testing"

func TestParseTraceparent(t *testing.T) {
	cases := []struct {
		in      string
		ok      bool
		sampled bool
	}{
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", true, true},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", true, false},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03", true, true},
		{"00-00000000000000000000000000000000-00f067aa0ba902b7-01", false, false},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", false, false},
		{"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", false, false},
		{"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", false, false},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		id, sampled, ok := ParseTraceparent(c.in)
		if ok != c.ok || (ok && (sampled != c.sampled || id != c.in[3:35])) {
			t.Errorf("%q: got (%q, %v, %v)", c.in, id, sampled, ok)
		}
	}
	i := Info{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7", Sampled: true}
	if got := i.Traceparent(); got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatalf("Traceparent() = %q", got)
	}
}
