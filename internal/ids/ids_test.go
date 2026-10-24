package ids

import "testing"

func TestRoundTrip(t *testing.T) {
	l := NewLease()
	if !ValidLease(l) {
		t.Fatalf("invalid lease %q", l)
	}
	e, got, err := Parse(Sandbox("e001", l))
	if err != nil || e != "e001" || got != l {
		t.Fatalf("parse: %v %q %q", err, e, got)
	}
	for _, bad := range []string{"", "e001", "E1." + l, "e001.short", "e001." + l + "!"} {
		if _, _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

func TestItemLease(t *testing.T) {
	k := NewLease()
	if !ValidRequestID(k) || ValidRequestID(k+"aaaa") || ValidRequestID("short") || ValidRequestID("ABCDEFGHIJKLMNOPQ") {
		t.Fatal("ValidRequestID")
	}
	seen := map[string]bool{}
	for _, i := range []int32{0, 1, 31, 32, 255, 1000, 32767} {
		l := ItemLease(k, i)
		if !ValidLease(l) || seen[l] {
			t.Fatalf("ItemLease(%d) = %q", i, l)
		}
		seen[l] = true
		if got, ok := ItemIndex(k, l); !ok || got != i {
			t.Fatalf("ItemIndex(%q) = %d, %v; want %d", l, got, ok, i)
		}
	}
	if _, ok := ItemIndex(k, NewLease()); ok {
		t.Fatal("ItemIndex matched a foreign lease")
	}
}
