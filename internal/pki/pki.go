// Package pki issues the cluster CA and component certificates used for
// mTLS between OpenDsec components (spec §14.1), and maps certificates back to
// component identities.
//
// A component's identity is the URI SAN "opendsec://<role>/<id>". Every
// certificate also carries the DNS SAN InternalName, which clients use as the
// TLS server name, plus the hosts of the component's listen address.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const InternalName = "opendsec.internal"

// APIServerName is carried by every apiserver certificate: clients that
// reach several apiservers, or a load balancer, verify it (the Python SDK
// and pkg/client do), whatever hosts the certificate was issued for.
const APIServerName = "api.opendsec.internal"

// Roles.
const (
	RoleIAM       = "iam"
	RoleWatcher   = "watcher"
	RoleAPIServer = "apiserver"
	RoleEdge      = "edge"
	RoleFleet     = "fleet" // cluster management service (spec §28)
	RoleNode      = "node"  // node agent, one per machine; id = node name
	RoleOps       = "ops"   // an operator's certificate, for opendsecctl fleet -direct
)

// Identity of a component.
type Identity struct {
	Role, ID string
}

func (i Identity) String() string { return i.Role + "/" + i.ID }

// FileName is the base name of the identity's cert/key files.
func (i Identity) FileName() string {
	if i.ID == "" {
		return i.Role
	}
	return i.Role + "-" + i.ID
}

func (i Identity) uri() *url.URL { return &url.URL{Scheme: "opendsec", Host: i.Role, Path: "/" + i.ID} }

// FromCert extracts the identity from a certificate's URI SAN.
func FromCert(c *x509.Certificate) (Identity, error) {
	for _, u := range c.URIs {
		if u.Scheme == "opendsec" && u.Host != "" {
			return Identity{Role: u.Host, ID: strings.TrimPrefix(u.Path, "/")}, nil
		}
	}
	return Identity{}, errors.New("certificate has no opendsec:// identity")
}

// CA is a certificate authority that can issue component certificates.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// NewCA creates a self-signed CA valid for the given duration.
func NewCA(name string, validity time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"opendsec"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return &CA{Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// Issue signs a certificate for id, valid as both TLS server and client.
// hosts are DNS names or IPs the component is reachable at.
func (ca *CA) Issue(id Identity, hosts []string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	notAfter := time.Now().Add(validity)
	if notAfter.After(ca.Cert.NotAfter) { // a certificate is worthless past its CA's expiry
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: id.String(), Organization: []string{"opendsec"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{InternalName},
		URIs:         []*url.URL{id.uri()},
	}
	if id.Role == RoleAPIServer {
		tmpl.DNSNames = append(tmpl.DNSNames, APIServerName)
	}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if !ip.IsUnspecified() { // a 0.0.0.0 listen address is not a reachable name
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			}
		} else if h != InternalName && !(id.Role == RoleAPIServer && h == APIServerName) {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

// WriteCA writes ca.crt and ca.key into dir.
func (ca *CA) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), ca.PEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

// LoadCA reads ca.crt and ca.key from dir.
func LoadCA(dir string) (*CA, error) {
	cb, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, errors.New("bad CA PEM")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, PEM: cb}, nil
}

// IssueTo issues a certificate for id and writes <name>.crt / <name>.key into dir.
func (ca *CA) IssueTo(dir string, id Identity, hosts []string, validity time.Duration) error {
	c, k, err := ca.Issue(id, hosts, validity)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, id.FileName()+".crt"), c, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, id.FileName()+".key"), k, 0o600)
}

// Material is what a component needs for TLS: the CA pool and its own keypair.
type Material struct {
	Self     Identity
	Pool     *x509.CertPool
	Cert     tls.Certificate // Leaf is set
	CAExpiry time.Time
}

// Load reads ca.crt plus the keypair of self from dir.
func Load(dir string, self Identity) (*Material, error) {
	cab, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cab) {
		return nil, fmt.Errorf("%s/ca.crt: no certificates", dir)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, self.FileName()+".crt"), filepath.Join(dir, self.FileName()+".key"))
	if err != nil {
		return nil, fmt.Errorf("keypair for %s: %w", self, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("certificate of %s: %w", self, err)
	}
	cert.Leaf = leaf
	m := &Material{Self: self, Pool: pool, Cert: cert}
	if b, _ := pem.Decode(cab); b != nil {
		if ca, err := x509.ParseCertificate(b.Bytes); err == nil {
			m.CAExpiry = ca.NotAfter
		}
	}
	return m, nil
}

// ServerConfig requires and verifies client certificates (internal APIs).
func (m *Material) ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{m.Cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: m.Pool,
	}
}

// PublicServerConfig serves TLS without client certificates (public API).
func (m *Material) PublicServerConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{m.Cert}}
}

// ClientConfig presents our certificate and verifies the server's chain. If
// expect is set, the server must also carry exactly that identity.
func (m *Material) ClientConfig(expect *Identity) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{m.Cert},
		RootCAs: m.Pool, ServerName: InternalName,
	}
	if expect != nil {
		want := *expect
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			got, err := FromCert(cs.PeerCertificates[0])
			if err != nil {
				return err
			}
			if got != want {
				return fmt.Errorf("server identity %s, want %s", got, want)
			}
			return nil
		}
	}
	return cfg
}

// HostOf returns the host part of a "host:port" address.
func HostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
