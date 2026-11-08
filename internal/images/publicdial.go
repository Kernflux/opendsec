package images

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"syscall"
	"time"
)

// nonPublic are the networks a pull for an untrusted user must not reach
// (spec §43.3): the cluster's own (apiservers, IAM, NFS, cloud metadata)
// are among them. A registry resolving to one is refused at connect time,
// after DNS, so a name pointing inside is refused too, as are redirects.
// IPv4-mapped IPv6 addresses are checked as IPv4 (To4).
var nonPublic = mustNets("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8")

func mustNets(cidrs ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// IsPublicIP reports whether ip is a public unicast address.
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range nonPublic {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// PublicClient is an HTTP client that connects only to public addresses,
// except to the registries allowed ("host:port", e.g. a mirror inside the
// network), and ignores proxy settings (a proxy would connect for it).
func PublicClient(timeout time.Duration, allowed []string) *http.Client {
	check := func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); !IsPublicIP(ip) {
			return fmt.Errorf("%s is not a public address: registries on private networks are not allowed", host)
		}
		return nil
	}
	pub := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: check}
	anyAddr := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if slices.Contains(allowed, addr) {
			return anyAddr.DialContext(ctx, network, addr)
		}
		return pub.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}
