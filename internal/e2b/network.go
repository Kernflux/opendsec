package e2b

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
)

// Network options and keeping sandboxes alive (spec §37.11).

// networkConfig is E2B's SandboxNetworkConfig (and its update), as far as
// OpenDsec's network rules (spec §20) express it.
type networkConfig struct {
	AllowOut   []string `json:"allowOut,omitempty"`
	DenyOut    []string `json:"denyOut,omitempty"`
	DNSServers []string `json:"dnsServers,omitempty"`
	// Sandbox ports always need a token (spec §37.8): true (E2B's
	// default) is accepted as it changes nothing for SDK callers.
	AllowPublicTraffic *bool           `json:"allowPublicTraffic,omitempty"`
	MaskRequestHost    string          `json:"maskRequestHost,omitempty"`
	HTTPSPorts         []int           `json:"httpsPorts,omitempty"`
	Rules              json.RawMessage `json:"rules,omitempty"`
	EgressProxy        json.RawMessage `json:"egressProxy,omitempty"`
}

// allTraffic is E2B's "everything" range (ALL_TRAFFIC).
const allTraffic = "0.0.0.0/0"

// networkRules maps E2B's network options to network rules. E2B allows the
// internet by default, as does a cluster whose default rules hold "*":
// allow_internet_access false or denyOut 0.0.0.0/0 take "*" back, and
// allowOut entries (allowed before denials, as in E2B) are rules of their
// own. Other denials cannot be expressed (OpenDsec allows by rule only).
func networkRules(internet *bool, n *networkConfig) (map[string]bool, error) {
	rules := map[string]bool{}
	if internet != nil && !*internet {
		rules["*"] = false
	}
	if n == nil {
		return rules, nil
	}
	switch {
	case n.MaskRequestHost != "", len(n.HTTPSPorts) > 0, unset(n.Rules), unset(n.EgressProxy):
		return nil, errors.New("network maskRequestHost, httpsPorts, rules and egressProxy are not supported by the OpenDsec E2B gateway")
	}
	for _, d := range n.DenyOut {
		if d != allTraffic {
			return nil, errors.New("denyOut supports only " + allTraffic + " in the OpenDsec E2B gateway: other destinations are denied unless allowed")
		}
		rules["*"] = false
	}
	for _, a := range n.AllowOut {
		switch {
		case a == allTraffic:
			rules["*"] = true
		case strings.HasPrefix(a, "*."): // a domain rule covers its subdomains (and the domain itself)
			rules[a[2:]] = true
		default:
			rules[a] = true
		}
	}
	return rules, nil
}

// networkOf is the network config a sandbox's rules amount to (nil for
// none of its own: the cluster's default rules).
func networkOf(rules map[string]bool) *networkConfig {
	if len(rules) == 0 {
		return nil
	}
	n := &networkConfig{}
	for k, v := range rules {
		switch {
		case k == "*" && v:
			n.AllowOut = append(n.AllowOut, allTraffic)
		case k == "*":
			n.DenyOut = append(n.DenyOut, allTraffic)
		case v:
			n.AllowOut = append(n.AllowOut, k)
		}
	}
	slices.Sort(n.AllowOut)
	return n
}

// unset reports whether a raw JSON field holds a value.
func unset(m json.RawMessage) bool {
	s := strings.TrimSpace(string(m))
	return s != "" && s != "null" && s != "{}" && s != "[]"
}

// updateNetwork replaces a sandbox's egress rules, as E2B's update.
func (g *Gateway) updateNetwork(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req networkConfig
	if !decode(w, r, &req) {
		return
	}
	rules, err := networkRules(nil, &req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sb, ok := g.sandbox(ctx, w, r)
	if !ok {
		return
	}
	if _, err := g.api.UpdateNetwork(ctx, &pb.UpdateNetworkRequest{SandboxId: sb.Id, Rules: rules, Replace: true}); err != nil {
		writeAPIErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// maxRefresh is E2B's bound on a refresh.
const maxRefresh = 3600

// refresh keeps a sandbox alive at least duration seconds from now.
func (g *Gateway) refresh(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Duration int64 `json:"duration"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Duration < 0 || req.Duration > maxRefresh {
		writeErr(w, http.StatusBadRequest, "duration must be between 0 and 3600")
		return
	}
	sb, ok := g.sandbox(ctx, w, r)
	if !ok {
		return
	}
	if req.Duration == 0 {
		req.Duration = 15 // E2B's default timeout
	}
	end := time.Unix(0, int64(sb.CreatedAt*1e9)).Add(time.Duration(sb.GetSpec().GetTtlMaxS()) * time.Second)
	if time.Until(end) < time.Duration(req.Duration)*time.Second {
		if _, err := g.api.SetSandboxTimeout(ctx, &pb.SetTimeoutRequest{SandboxId: sb.Id, TimeoutS: g.timeout(req.Duration)}); err != nil {
			writeAPIErr(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
