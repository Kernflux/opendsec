package rpcutil

import (
	"testing"

	"github.com/kernflux/opendsec/internal/pki"
)

// Apiservers take IAM locks (for image publishes); edges do not.
func TestIAMLockACL(t *testing.T) {
	for _, m := range []string{"/opendsec.v1.IAM/AcquireLock", "/opendsec.v1.IAM/ReleaseLock"} {
		if !IAMACL.allows(m, pki.RoleAPIServer) || !IAMACL.allows(m, pki.RoleFleet) || IAMACL.allows(m, pki.RoleEdge) {
			t.Errorf("%s: apiserver %v fleet %v edge %v", m, IAMACL.allows(m, pki.RoleAPIServer),
				IAMACL.allows(m, pki.RoleFleet), IAMACL.allows(m, pki.RoleEdge))
		}
	}
}
