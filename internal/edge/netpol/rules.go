package netpol

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kernflux/opendsec/internal/config"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// AllowAll is the rule allowing every public destination.
const AllowAll = "*"

// targets are destinations: domains (and their subdomains) through the DNS
// proxy, IPv4 networks directly, or all public addresses.
type targets struct {
	all     bool
	domains []string // lower case, no trailing dot
	nets    []*net.IPNet
}

func (t *targets) allowsName(name string) bool {
	if t.all {
		return true
	}
	for _, d := range t.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// portSpec limits targets to a protocol and a destination port range
// (spec §29.2); the zero value allows every port and protocol.
type portSpec struct {
	proto  byte   // unix.IPPROTO_TCP or IPPROTO_UDP; 0: both
	lo, hi uint16 // 0, 0: any port
}

func (s portSpec) any() bool { return s.lo == 0 }

func (s portSpec) String() string {
	out := strconv.Itoa(int(s.lo))
	if s.hi != s.lo {
		out += "-" + strconv.Itoa(int(s.hi))
	}
	switch s.proto {
	case unix.IPPROTO_TCP:
		out += "/tcp"
	case unix.IPPROTO_UDP:
		out += "/udp"
	}
	return out
}

// protos are the protocols the spec covers.
func (s portSpec) protos() []byte {
	if s.proto != 0 {
		return []byte{s.proto}
	}
	return []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP}
}

// limited is the targets allowed on some ports only.
type limited struct {
	ports portSpec
	targets
}

// policy is what a sandbox may reach: targets on any port and protocol,
// and targets limited to ports (sorted by port spec).
type policy struct {
	targets
	limited []*limited
}

// splitPorts splits "target[:ports[/proto]]": ports is a port or a range
// lo-hi, proto tcp or udp (default both). IPv4 only, so the first ':' ends
// the target.
func splitPorts(entry string) (string, portSpec, error) {
	target, rest, ok := strings.Cut(entry, ":")
	if !ok {
		return entry, portSpec{}, nil
	}
	var s portSpec
	ports, proto, hasProto := strings.Cut(rest, "/")
	if hasProto {
		switch proto {
		case "tcp":
			s.proto = unix.IPPROTO_TCP
		case "udp":
			s.proto = unix.IPPROTO_UDP
		default:
			return "", s, fmt.Errorf("%q: protocol %q is not tcp or udp", entry, proto)
		}
	}
	port := func(v string) (uint16, error) {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("%q: %q is not a port (1-65535)", entry, v)
		}
		return uint16(n), nil
	}
	lo, hi, isRange := strings.Cut(ports, "-")
	var err error
	if s.lo, err = port(lo); err != nil {
		return "", s, err
	}
	s.hi = s.lo
	if isRange {
		if s.hi, err = port(hi); err != nil {
			return "", s, err
		}
		if s.hi < s.lo {
			return "", s, fmt.Errorf("%q: empty port range", entry)
		}
	}
	return target, s, nil
}

// compile merges rules over the cluster defaults into a policy. A rule is a
// rule set name, or an entry: AllowAll, a domain or an IPv4 CIDR (or
// address), optionally with ":ports[/proto]" (pypi.org:443,
// 10.0.0.0/8:5432/tcp, *:443); true allows it, false takes it back (from
// the defaults).
func compile(np *config.NetworkPolicy, rules map[string]bool) (*policy, error) {
	eff := map[string]bool{}
	for k, v := range np.DefaultRules {
		eff[k] = v
	}
	for k, v := range rules {
		eff[k] = v
	}
	keys := make([]string, 0, len(eff))
	for k := range eff {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	p := &policy{}
	byPorts := map[portSpec]*limited{}
	seen := map[string]bool{}
	var add func(entry string, from string) error
	add = func(entry, from string) error {
		entry = strings.ToLower(strings.TrimSpace(entry))
		entry, ports, err := splitPorts(entry)
		if err != nil {
			return fmt.Errorf("%s: %v", from, err)
		}
		t := &p.targets
		if !ports.any() {
			l := byPorts[ports]
			if l == nil {
				l = &limited{ports: ports}
				byPorts[ports] = l
				p.limited = append(p.limited, l)
			}
			t = &l.targets
		}
		switch {
		case entry == AllowAll:
			t.all = true
		case strings.Contains(entry, "/") || net.ParseIP(entry) != nil:
			cidr := entry
			if !strings.Contains(cidr, "/") {
				cidr += "/32"
			}
			_, n, err := net.ParseCIDR(cidr)
			if err != nil || n.IP.To4() == nil {
				return fmt.Errorf("%s: %q is not an IPv4 address or network", from, entry)
			}
			t.nets = append(t.nets, n)
		default:
			d := strings.TrimSuffix(strings.TrimPrefix(entry, "*."), ".")
			if !validDomain(d) {
				return fmt.Errorf("%s: %q is not a domain", from, entry)
			}
			if k := ports.String() + " " + d; !seen[k] {
				seen[k] = true
				t.domains = append(t.domains, d)
			}
		}
		return nil
	}
	for _, k := range keys {
		if !eff[k] {
			continue
		}
		if set, ok := np.RuleSets[k]; ok {
			for _, e := range set {
				if err := add(e, "rule set "+k); err != nil {
					return nil, rpcutil.Err(rpcutil.Invalid, "%v", err)
				}
			}
			continue
		}
		if err := add(k, "network rule"); err != nil {
			return nil, rpcutil.Err(rpcutil.Invalid, "%v (and no rule set has that name)", err)
		}
	}
	sort.Slice(p.limited, func(i, j int) bool { return p.limited[i].ports.String() < p.limited[j].ports.String() })
	return p, nil
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// allowsName reports whether name (lower case, no trailing dot) may be
// resolved: it is an allowed domain or one of its subdomains, on some port.
func (p *policy) allowsName(name string) bool {
	anyPort, ks := p.learnSets(name)
	return anyPort || len(ks) > 0
}

// learnSets says where addresses resolved for name go: the set of
// addresses reachable on any port (anyPort), and the port-limited ones
// (indexes into p.limited).
func (p *policy) learnSets(name string) (anyPort bool, limitedIdx []int) {
	anyPort = p.targets.allowsName(name)
	for i, l := range p.limited {
		if l.targets.allowsName(name) {
			limitedIdx = append(limitedIdx, i)
		}
	}
	return anyPort, limitedIdx
}
