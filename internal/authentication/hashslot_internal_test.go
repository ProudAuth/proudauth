package authentication

import (
	"context"
	"net/http"
	"testing"

	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/slots"
)

// TestHashSlotFailsFast covers NFR-002: password hashing is bounded per
// process; with every slot in use a password step is refused at once with
// 503 unavailable and Retry-After, and work nested under a held
// slot (a password change's check and new verifier) does not take a second.
func TestHashSlotFailsFast(t *testing.T) {
	s := &Service{Hasher: &credential.Hasher{Slots: slots.New(1)}}
	ctx, release, err := s.hashSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, inner, err := s.hashSlot(ctx); err != nil {
		t.Fatalf("nested work under a held slot was refused: %v", err)
	} else {
		inner()
	}
	_, _, err = s.hashSlot(context.Background())
	pe, ok := problem.As(err)
	if !ok || pe.Status != http.StatusServiceUnavailable || pe.Code != "unavailable" || pe.RetryAfter <= 0 {
		t.Fatalf("full hashing bound: %v", err)
	}
	release()
	if _, again, err := s.hashSlot(context.Background()); err != nil {
		t.Fatalf("a released slot was not reusable: %v", err)
	} else {
		again()
	}
}
