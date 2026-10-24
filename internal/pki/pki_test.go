package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/kernflux/opendsec/pkg/client"
)

// The Apache-2.0 client carries its own copy of the name (NOTICE).
func TestClientAPIServerName(t *testing.T) {
	if client.APIServerName != APIServerName {
		t.Fatalf("pkg/client says %q, pki %q", client.APIServerName, APIServerName)
	}
}

func TestIssueAndIdentity(t *testing.T) {
	ca, err := NewCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Role: RoleEdge, ID: "e001"}
	certPEM, _, err := ca.Issue(id, []string{"10.0.0.7", "node7.example"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromCert(cert)
	if err != nil || got != id {
		t.Fatalf("identity = %v %v", got, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	for _, name := range []string{InternalName, "node7.example", "10.0.0.7"} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: name,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("verify for %s: %v", name, err)
		}
	}
	if id.FileName() != "edge-e001" || (Identity{Role: RoleIAM}).FileName() != "iam" ||
		(Identity{Role: RoleIAM, ID: "2"}).FileName() != "iam-2" {
		t.Fatal("file names")
	}
}

func TestValidityCappedByCA(t *testing.T) {
	ca, err := NewCA("t", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := ca.Issue(Identity{Role: RoleEdge, ID: "e1"}, nil, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(c)
	leaf, _ := x509.ParseCertificate(b.Bytes)
	if leaf.NotAfter.After(ca.Cert.NotAfter) {
		t.Fatalf("leaf expires %v, after its CA %v", leaf.NotAfter, ca.Cert.NotAfter)
	}
}
