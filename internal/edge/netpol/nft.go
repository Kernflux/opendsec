package netpol

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Host-side filtering (spec §20.2), one nftables table per edge:
//
//   - new connections into a sandbox are dropped (other sandboxes, the
//     host, the outside); replies pass;
//   - every packet a sandbox sends goes to its own chain, keyed by its veth
//     and its address (a forged source address matches nothing and is
//     dropped), established connections included: taking a rule back cuts
//     its connections at once;
//   - its chain accepts its allowed networks, drops private, link-local and
//     multicast destinations, accepts the addresses its DNS proxy learned
//     for allowed domains (expiring once idle for an hour), else drops;
//   - DNS to the sandbox's gateway is redirected to the edge's proxy; no
//     other host service is reachable; sandbox traffic is masqueraded out.

var privateNets = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"}

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s\nscript:\n%s", err, bytes.TrimSpace(out), script)
	}
	return nil
}

// baseRules (re)creates the edge's table and its base chains, keeping the
// per-sandbox chains and sets.
func (m *Manager) baseRules() string {
	t, p, pool, port := m.table, m.prefix+"*", m.pool.String(), m.dnsPort
	return fmt.Sprintf(`add table inet %[1]s
add set inet %[1]s private { type ipv4_addr; flags interval; }
flush set inet %[1]s private
add element inet %[1]s private { %[5]s }
add map inet %[1]s sb { type ifname . ipv4_addr : verdict; }
add chain inet %[1]s forward { type filter hook forward priority filter; policy accept; }
flush chain inet %[1]s forward
add rule inet %[1]s forward iifname "%[2]s" meta nfproto ipv6 drop
add rule inet %[1]s forward oifname "%[2]s" ct state established,related accept
add rule inet %[1]s forward oifname "%[2]s" drop
add rule inet %[1]s forward iifname "%[2]s" iifname . ip saddr vmap @sb
add rule inet %[1]s forward iifname "%[2]s" drop
add chain inet %[1]s input { type filter hook input priority filter; policy accept; }
flush chain inet %[1]s input
add rule inet %[1]s input iifname "%[2]s" ip daddr %[3]s udp dport %[4]d accept
add rule inet %[1]s input iifname "%[2]s" ip daddr %[3]s tcp dport %[4]d accept
add rule inet %[1]s input iifname "%[2]s" ct state established,related accept
add rule inet %[1]s input iifname "%[2]s" drop
add rule inet %[1]s input iifname != "%[2]s" udp dport %[4]d drop
add rule inet %[1]s input iifname != "%[2]s" tcp dport %[4]d drop
add chain inet %[1]s prerouting { type nat hook prerouting priority dstnat; policy accept; }
flush chain inet %[1]s prerouting
add rule inet %[1]s prerouting iifname "%[2]s" ip daddr %[3]s udp dport 53 redirect to :%[4]d
add rule inet %[1]s prerouting iifname "%[2]s" ip daddr %[3]s tcp dport 53 redirect to :%[4]d
add chain inet %[1]s postrouting { type nat hook postrouting priority srcnat; policy accept; }
flush chain inet %[1]s postrouting
add rule inet %[1]s postrouting ip saddr %[3]s oifname != "%[2]s" masquerade
`, t, p, pool, port, strings.Join(privateNets, ", "))
}

// learnIdle: a learned address stays allowed while it is used, until idle
// this long (or its domain is taken back).
const learnIdle = time.Hour
