// Package ids defines sandbox identifiers.
//
// A sandbox id is "<edge_id>.<lease>". Encoding the owning edge lets any
// stateless apiserver instance route an operation without a lookup (paper §3).
// The lease is random and doubles as the IAM quota-reservation key, so it does
// not change when a creation is retried on a different edge.
package ids

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"
)

var (
	edgeRe  = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	leaseRe = regexp.MustCompile(`^[a-z2-7]{16,32}$`)
	enc     = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// NewLease returns a fresh random lease (26 lowercase base32 chars).
func NewLease() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return strings.ToLower(enc.EncodeToString(b[:]))
}

func ValidEdgeID(id string) bool { return edgeRe.MatchString(id) }
func ValidLease(l string) bool   { return leaseRe.MatchString(l) }

// itemDigits is how many base32 chars ItemLease appends: 32^3 covers a
// batch of 32768.
const itemDigits = 3

// ValidRequestID reports whether k can key a batch: ItemLease(k, i) must
// be a valid lease.
func ValidRequestID(k string) bool {
	return len(k) >= 16 && len(k)+itemDigits <= 32 && leaseRe.MatchString(k)
}

// ItemLease is the lease of item i (< 32768) of a batch keyed by k: a retry
// of the batch derives the same leases, and so finds what it made.
func ItemLease(k string, i int32) string {
	const digits = "abcdefghijklmnopqrstuvwxyz234567"
	b := []byte(k)
	for d := itemDigits - 1; d >= 0; d-- {
		b = append(b, digits[(i>>(5*d))&31])
	}
	return string(b)
}

// ItemIndex is the inverse of ItemLease: the item lease l stands for in
// the batch keyed by k.
func ItemIndex(k, l string) (int32, bool) {
	if len(l) != len(k)+itemDigits || !strings.HasPrefix(l, k) {
		return 0, false
	}
	var i int32
	for _, c := range l[len(k):] {
		v := strings.IndexRune("abcdefghijklmnopqrstuvwxyz234567", c)
		if v < 0 {
			return 0, false
		}
		i = i<<5 | int32(v)
	}
	return i, true
}

// Sandbox joins an edge id and a lease into a sandbox id.
func Sandbox(edgeID, lease string) string { return edgeID + "." + lease }

// Parse splits a sandbox id into its edge id and lease.
func Parse(id string) (edgeID, lease string, err error) {
	e, l, ok := strings.Cut(id, ".")
	if !ok || !ValidEdgeID(e) || !ValidLease(l) {
		return "", "", fmt.Errorf("malformed sandbox id %q", id)
	}
	return e, l, nil
}
