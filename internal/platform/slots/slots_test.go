package slots

import "testing"

func TestPoolFailsFastWhenFull(t *testing.T) {
	p := New(2)
	r1, ok1 := p.TryAcquire()
	r2, ok2 := p.TryAcquire()
	if !ok1 || !ok2 {
		t.Fatal("free slots refused")
	}
	if _, ok := p.TryAcquire(); ok {
		t.Fatal("a full pool handed out a third slot")
	}
	r1()
	r3, ok := p.TryAcquire()
	if !ok {
		t.Fatal("a released slot was not reusable")
	}
	r2()
	r3()
	if p.Size() != 2 {
		t.Fatalf("size %d", p.Size())
	}
}

func TestNilPoolIsUnbounded(t *testing.T) {
	p := New(0)
	for i := 0; i < 100; i++ {
		r, ok := p.TryAcquire()
		if !ok {
			t.Fatal("unbounded pool refused")
		}
		defer r()
	}
	if p.Size() != 0 {
		t.Fatalf("size %d", p.Size())
	}
}
