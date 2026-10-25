# Network policy

Sandbox networking denies everything by default: a sandbox can neither connect out nor be connected to. Callers allow the destinations they need; administrators define rule sets and cluster-wide default rules. This page covers how to write rules, how they are enforced, and the edge cases.

It assumes the node has sandbox networking enabled (`edges[].network.enabled`, on in the single-node install and the example configs). On nodes without it, sandboxes only have a loopback interface and `network_rules` is ignored.

## 1. Writing rules

`network_rules` is a dict: each key is a rule, `true` allows it, `false` takes it back.

| Rule | Example | Meaning |
|---|---|---|
| Rule set name | `pypi` | A group of destinations the administrator defined in `network.rule_sets` |
| Domain | `github.com` | The domain and all its subdomains (`api.github.com`, `raw.github.com`, …). `*.github.com` means the same |
| IPv4 address | `1.2.3.4` | That address |
| IPv4 network | `203.0.113.0/24`, `10.20.0.0/16` | The whole network |
| `*` | `*` | Every **public** address (private ones excluded; see §4) |

Any rule can be limited to ports with `:port[/protocol]`:

| Rule | Meaning |
|---|---|
| `pypi.org:443` | Port 443 only, TCP or UDP |
| `10.0.0.0/8:5432/tcp` | TCP 5432 only |
| `*:443` | Port 443 of every public address |
| `example.com:8000-8080` | A port range |
| `1.1.1.1:53/udp` | UDP 53 only |

Entries of rule sets can carry ports too.

IPv4 only: sandboxes have IPv4 addresses only, and AAAA queries get empty answers.

### Examples

```python
# Python packages only
DSecRunArgs(..., network_rules={"pypi": True})

# the internet, HTTPS only
DSecRunArgs(..., network_rules={"*:443": True})

# the internet, plus one database on the internal network
DSecRunArgs(..., network_rules={"*": True, "10.20.0.15:5432/tcp": True})

# the cluster allows the internet by default; not for this sandbox
DSecRunArgs(..., network_rules={"*": False})

# the cluster allows the internet by default; this sandbox gets PyPI on 443 only
DSecRunArgs(..., network_rules={"*": False, "pypi.org:443": True, "files.pythonhosted.org:443": True})
```

On the command line, `-net` takes rules comma separated, with `!` for `false`:

```sh
opendsecctl sandbox create -backend microvm -image root/py:3.12 -net 'pypi,github.com:443'
opendsecctl sandbox create -backend microvm -image root/py:3.12 -net '!*'
```

## 2. Rule sets and default rules (administrators)

In the cluster config's `network` section ([configuration reference](CONFIGURATION.md#network)):

```json
"network": {
  "rule_sets": {
    "pypi":   ["pypi.org", "files.pythonhosted.org"],
    "npm":    ["registry.npmjs.org"],
    "github": ["github.com", "codeload.github.com", "objects.githubusercontent.com"],
    "mirror": ["10.30.0.10:443/tcp"]
  },
  "default_rules": {"mirror": true},
  "upstream_dns": ["10.0.0.2"]
}
```

- **Rule sets** name common destinations, so callers write `{"pypi": true}` without knowing the domains. A rule set applies only when `network_rules` names it.
- **Default rules** apply to every sandbox, under its own `network_rules`: for the same key, the sandbox's value wins, so callers can take a default back with `false`.
  - For internet access by default: `"default_rules": {"*": true}`.
  - The single-node install (quickstart) has no default rules: sandboxes reach nothing by default.
  - Sandboxes created through the E2B gateway get internet access by default, as on E2B, unless the request turns it off ([Migrating from E2B](E2B.md)).
- **Upstream DNS**: the resolvers the edges' DNS proxies query; default: the host's `/etc/resolv.conf`. Set them when the internal network has its own DNS.

## 3. Enforcement

Each edge enforces the rules with nftables and a DNS proxy:

- **Outbound**: every packet a sandbox sends goes through its own chain, in this order:
  1. accept the addresses and networks its rules name (with their port limits);
  2. drop private, link-local and multicast destinations;
  3. accept addresses the DNS proxy resolved for it from allowed domains;
  4. drop the rest.
- **DNS**: the sandbox's DNS queries are redirected to the edge's DNS proxy.
  - Allowed domains: the query goes upstream, and the IPv4 addresses in the answer are added to the sandbox's allowed set before it gets the answer, so a connection can always use an address it just resolved.
  - Other domains: NXDOMAIN (no such domain).
  - With `*` allowed, every name resolves.
  - Addresses learned this way expire after an hour unused; resolving the name again adds them back.
- **Inbound**: every new connection to a sandbox is dropped, whether from another sandbox, the host or outside. Replies to connections the sandbox opened pass.
- **Spoofing**: packets with a forged source address match no rule and are dropped.
- **Host services**: apart from DNS, a sandbox reaches no service on its host.
- **Egress**: sandbox traffic leaves through the host with masquerading; the outside sees the node's address.

To reach a service running in a sandbox, do not go over the network: use the SDK's `sb.http()`, the API's `ConnectPort`, or the E2B gateway's port forwarding. These enter the sandbox's network namespace from the edge and do not pass the rules above.

## 4. Private addresses

These ranges are reachable only through an **address or network rule naming them**:

`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16` (cloud metadata `169.254.169.254` included), `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`

- `*` does not include them.
- Private addresses a domain resolves to are always blocked, even for an allowed domain. This stops DNS from being used to get around the rules.
- To reach one internal service (a database, a package mirror, a model server), name its address and port in a network rule, e.g. `10.30.0.10:443/tcp`. Allow only what is needed: allowing whole private ranges lets code in the sandbox reach cluster nodes and other internal services.

## 5. Changing rules at run time

```python
await sb.update_network({"github": True})                 # merge: add a rule
await sb.update_network({"github": False})                # take it back
await sb.update_network({"pypi": True}, replace=True)     # replace: only this rule (the defaults still apply)
```

```sh
opendsecctl sandbox network $ID github
opendsecctl sandbox network $ID '!github'
opendsecctl sandbox network $ID pypi -replace
```

- Needs `sandbox.operate`.
- New allowances apply at once.
- **Taking an allowance back applies at once and cuts existing connections**: their later packets go through the chain too.
- The new rules are written into the sandbox's spec; `get_sandbox` shows the current ones.

## 6. Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| `Could not resolve host` / no such domain | The domain is not allowed (the DNS proxy answers NXDOMAIN) | `sb.info.spec.network_rules` and the cluster's `default_rules`; subdomains are covered, parent domains are not |
| Resolves, but the connection times out | A port limit does not match; or the name resolves to a private address | Try a rule without ports; `getent hosts <domain>` shows what it resolves to |
| An internal service times out | Private addresses need an explicit network rule | Add `<address>:<port>/tcp` |
| A rule is `invalid` | Not a valid domain, IPv4 address or network; a port outside 1–65535; a protocol other than tcp or udp | The message names the offending entry |
| No rule works, and the sandbox only has `lo` | The node has no sandbox networking | The administrator checks `edges[].network.enabled` |
| pip through a proxy or mirror fails | The mirror's domain is not in the rules | Add the mirror to a rule set, or use a network rule |

Checking from inside the sandbox:

```sh
cat /etc/resolv.conf                      # DNS points at the sandbox's gateway
getent hosts pypi.org                     # allowed domains resolve
python3 -c 'import urllib.request as u; print(u.urlopen("https://pypi.org/simple/", timeout=5).status)'
```
