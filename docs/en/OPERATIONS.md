# OpenDsec operations manual

This manual covers installing a multi-node production cluster, day-to-day operations and handling failures. The design background is in SPEC §27 (Chinese), the components in `deploy/README.md`. To try OpenDsec on one machine, see `deploy/quickstart.sh` ([Single-node install](INSTALL.md)). The step-by-step first deployment is in [Cluster deployment](CLUSTER.md).

## 1. Topology

Using the example inventory `deploy/prod/inventory.example`:

| Node | Components | Notes |
|---|---|---|
| ctl-1, ctl-2, ctl-3 | one replica each of iam, watcher, apiserver and fleet; ctl-3 also runs Prometheus and Alertmanager | control-plane nodes, one per failure domain, 4 cores and 8 GB to start, no sandboxes |
| node-a1, node-b1, node-c1 … | edge, node agent | compute nodes: bare metal or cloud VMs with nested virtualization, running sandboxes |

- The cluster keeps creating and serving sandboxes with any one control-plane node down. When a compute node fails, its sandboxes are lost and new ones go to other nodes.
- In a small cluster, control-plane components and edges can share machines (several roles on one inventory line).
- Shared storage (a NAS) is mounted at `/mnt/opendsec-images` on every apiserver and edge node, holding images and snapshots.
- An internal load balancer (LB below) listens on port 7100 (layer-4 TCP) in front of every apiserver. Clients use only the LB's address.

### Ports (open only inside the VPC)

| Port | Use | Who connects |
|---|---|---|
| 7100 | apiserver public API (TLS) | LB, ops machine |
| 7001 / 7011 | IAM gRPC / Raft replication | every component / IAM replicas |
| 7002 | watcher | apiserver, edge |
| 7201 | edge | watcher, apiserver, other edges, fleet |
| 7300 | fleet (cluster management, §6) | node agents, apiserver, other fleet replicas |
| 7400 | E2B gateway (optional, §4) | callers using the E2B SDK, LB |
| 9461–9467 | metrics, `/healthz`, `/readyz` (iam, watcher, apiserver, edge, fleet, node agent, E2B gateway) | Prometheus, LB health checks (9463; E2B gateway 9467), node agents (local) |
| 9100 | node_exporter | Prometheus |
| 9090 / 9093 | Prometheus / Alertmanager | operators |

### Infrastructure requirements
- **NAS**: NFS 4.1 or newer, with root squash turned off (on the NAS, "no root restriction" in the permission group). Edges write snapshots as root and apiservers delete them.
  - Once mounted, and before moving anything onto it, run `opendsecctl image store-check -store /mnt/<new mount point>` (no cluster needed); every required item must be ok. Missing `trusted.*` xattr support is fine (SPEC §29.5).
  - Mount options: `vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev`. 4.1 works too, but cannot find the holes of sparse files: creating a sandbox from a memory snapshot on another node then reads the disk and memory at full size (more than twice as slow in our tests; `store-check` warns about it). `lookupcache=positive` stops the client from caching "file not found": without it, a node that looked for an image before it was registered could keep missing it for up to a minute (SPEC §30).
  - fstab line: `<nas>:/ /mnt/opendsec-images nfs4 vers=4.2,nconnect=8,hard,timeo=600,lookupcache=positive,_netdev 0 0`.
  - Each node needs a distinct NFS client identity. Without one, an NFSv4 client identifies itself by host name, and nodes with the same host name (cloned from one image, say) are taken by the server for one client and keep invalidating each other's open files and locks (SPEC §33.4). `deploy/node/install.sh` sets the identity from `/etc/machine-id` (`/etc/modprobe.d/opendsec-nfs.conf`); a new identity takes effect only on a fresh mount with no users of the old one, most simply after a reboot. To check: on the NFS server, the `name` in `/proc/fs/nfsd/clients/*/info` should differ for every node; or watch the server's syslog for `rpc.mountd` printing `client attached/detached` over and over.
- **LB** (a cloud layer-4 load balancer, or HAProxy / LVS of your own):
  - Listen on TCP 7100; no layer-7 HTTP/gRPC listener: the apiservers terminate TLS themselves.
  - HTTP health check on port 9463, path `/readyz`, every 2 seconds, unhealthy after 2 failures.
  - Idle timeout of at least 30 seconds: the apiservers ping idle connections every 20 seconds, so quiet streams (batch creations, long commands) are not cut by the LB.
  - Keep the client's source address if the LB can; otherwise rate-limited authentication failures all count against the LB (see `deploy/README.md`, "Admission and rate limits").
  - The apiserver certificates must contain the LB's address: run `opendsecops certs <LB address>`, then `opendsecops push-config all` and `opendsecops restart`.

**Data centers without internet access**: use the offline bundle (`deploy/offline/README.md`, SPEC §38). The steps are the same as below, except that packages come from `OPENDSEC_DEBS`, the release from `opendsecops release-add`, and images from files.

## 2. The ops machine and opendsecops

The ops machine can be any machine that reaches every node over ssh (a control-plane node too). Its directory is `/root/opendsec-ops` by default (`OPENDSEC_OPS` changes it); the ssh key defaults to `/root/.ssh/opendsec-ops` (`OPENDSEC_SSH_KEY`). Contents:

```
inventory      nodes and roles (see deploy/prod/inventory.example)
opendsec.json  cluster config (see deploy/prod/cluster.example.json)
admin.token    admin token, mode 0600
pki/           the cluster CA (ca.key lives only here)
releases/      packaged releases
backups/       IAM backups
current ->     releases/<current version>
```

`deploy/prod/opendsecops help` lists every command. Common ones:

| Command | Effect |
|---|---|
| `opendsecops release bin/` | Package what `make build` produced into a release (version from `opendsecctl version`) |
| `opendsecops certs [LB address]` | Create the CA and certificates; with an LB address, reissue the apiserver certificates |
| `opendsecops install all` | First install: users and directories, release, config, certificates, systemd units, node preparation. Starts nothing |
| `opendsecops start all` | Start in the order IAM → watcher → apiserver → edge and wait until all are ready |
| `opendsecops status` | Check every component's `/readyz` and show the current IAM leader |
| `opendsecops versions` | The version each component runs |
| `opendsecops upgrade <version>` | Rolling upgrade |
| `opendsecops rollback <old version>` | Roll back: the same procedure onto an older release |
| `opendsecops push-config all` + `opendsecops restart` | After changing the config or certificates: deliver, then rolling restart |
| `opendsecops backup` | One IAM backup onto the ops machine, now |
| `opendsecops rotate-ca 1\|2\|3` | Rotate the cluster CA without downtime (§4, "Certificates") |
| `opendsecops monitor [webhook]` | Install node_exporter, Prometheus and Alertmanager, with alerts to the webhook |

Each node receives only `ca.crt` and its own components' certificates and keys. `admin.token` goes only to IAM nodes, which need it at startup; the cluster config names `admin_token_file`, never the token itself.

## 3. First install

```sh
make build && deploy/prod/opendsecops release bin/
# edit $OPENDSEC_OPS/inventory and opendsec.json, write admin.token (dsk.admin.<32 random hex digits>)
deploy/prod/opendsecops certs <LB address>
deploy/prod/opendsecops install all
# mount the NAS at /mnt/opendsec-images on each node (fstab)
deploy/prod/opendsecops start all
deploy/prod/opendsecops monitor <alert webhook>
deploy/prod/opendsecops status
```

Moving from a single IAM (an `iam.state` file) to three replicas:
1. On the old cluster: `opendsecctl iam backup -out iam.json.gz`.
2. Stop the old services and `install` and `start` with the new config. The new IAM bootstraps with the same admin token.
3. `opendsecctl iam restore iam.json.gz`.
4. Quota leases are not in backups. Sandboxes already on the edges are registered with IAM again at the next reconciliation (`reconcile_interval`, default 30 s).

## 4. Day-to-day operations

### Upgrades
```sh
make build && deploy/prod/opendsecops release bin/
deploy/prod/opendsecops upgrade <new version>
```
- The sequence:
  1. deliver the new release to every node and check its sha256;
  2. restart components one by one, each only after the previous one's `/readyz` returns 200;
  3. IAM followers first, the leader last;
  4. then watchers, apiservers and edges. After each edge restarts, wait until it is healthy again in the cluster snapshot.
- If any step times out (`OPENDSEC_READY_TIMEOUT`, default 180 s), it stops there. Components already upgraded keep the new version; to go back, `opendsecops rollback <old version>`.
- On SIGTERM, an apiserver first fails `/readyz` and keeps serving 6 more seconds while the LB takes it out, then gives calls in flight up to 30 seconds. The SDK retries broken calls and resumes streams (SPEC §26).
- Edge restarts do not touch sandboxes, provided `keep_sandboxes_on_exit` and `persist_state` are set and the unit uses `KillMode=process`. The new edge process re-adopts them.
- Each node keeps the last 3 releases (`OPENDSEC_KEEP_RELEASES`). Running sandboxes keep the agents of the release they started with.

### Maintaining a machine
```sh
opendsecctl edge drain node-a1   # stop placing new sandboxes on node-a1; existing ones keep running
# wait for its sandboxes to end; paused ones can move (SPEC §26.2)
systemctl stop opendsec-edge                # on node-a1; on a control-plane node, opendsec-{apiserver,watcher,fleet,iam}@<id>
# maintain..., then start the services again and run:
opendsecctl edge drain node-a1 -undo
```
Maintain only one IAM node at a time, or the majority is lost.

Rebooting a machine follows the same steps (drain → `systemctl reboot` → checks → `drain -undo`). After the reboot, check: `/data`, `/mnt/opendsec-images` and swap are mounted, `sysctl vm.swappiness` is 10, all four `/readyz` return 200, and the edge is healthy again in `opendsecctl status`.

Notes:
- A machine reboot loses all its sandboxes, paused microVMs included: when the edge re-adopts one and finds its network namespace gone, it removes it with its snapshot, and callers then get not_found.
- During the reboot, Prometheus fires `OpenDsecComponentDown`, `OpenDsecEdgeUnhealthy` and the like; Alertmanager needs a receiver (`opendsecops monitor <webhook>`), or the alerts reach nobody.
- A measured reboot (bare metal, about 107 s of firmware self-test) is in SPEC §27.

### Certificates
- Component certificates are valid 825 days, but never past the CA's expiry; the CA is valid 10 years. `OpenDsecCertExpiringSoon` fires 30 days before expiry.
- **Renewing component certificates**: on the ops machine, delete the `.crt` and `.key` concerned, run `opendsecops certs` to reissue them (the LB addresses are kept), then `opendsecops push-config all` and `opendsecops restart`.
- **Rotating the CA without downtime**: three steps, each with a config push and a rolling restart.
  1. `opendsecops rotate-ca 1`: create a new CA; every node trusts both the old and the new CA, component certificates unchanged for now.
  2. `opendsecops rotate-ca 2`: reissue every component certificate from the new CA.
  3. `opendsecops rotate-ca 3`: drop the old CA.

  After step 1, give every client `$OPENDSEC_OPS/pki/ca.crt` (both CAs); after step 3, again (the new CA only).
  - Why three steps: until restarted, components use their old certificates and trust lists. Reissuing straight from a new CA would make restarted and not-yet-restarted components reject each other.

### Adding edges
With fleet (§6), add machines with `opendsecops add-node` and `opendsecctl fleet node accept` (§6.3). Before fleet:
1. Add an entry to `edges` in `opendsec.json` and a line to the inventory.
2. `opendsecops certs` (issues the new edge's certificate).
3. `opendsecops install <node>`, `opendsecops push-config all`, `opendsecops restart`, `opendsecops start <node>`, in that order.

### Onboarding a tenant
```sh
export OPENDSEC_ADDR=<LB address>:7100 OPENDSEC_TOKEN=$(cat $OPENDSEC_OPS/admin.token) OPENDSEC_CA=$OPENDSEC_OPS/pki/ca.crt
opendsecctl project create root <name> -quota sandboxes=<N>
opendsecctl principal create root/<name> <caller> -kind agent          # the token is shown only in this output
opendsecctl grant root/<name> <caller> sandbox.create,sandbox.operate
opendsecctl grant root <caller> layer.use                            # may use the images under root/
```
- A caller's onboarding package: the [caller guide](USER_GUIDE.md) (with the address and project filled in), the SDK wheel, `ca.crt`, `sdk/python/examples/quickstart.py` and the token. Send the token separately over a secure channel.
- Tokens last at most 90 days (`max_token_ttl_s`). Before expiry, issue a new one with `opendsecctl token create <caller>`, and once the caller has switched, revoke the old one with `opendsecctl token revoke`.

### Usage (SPEC §41)
```sh
opendsecctl usage root/<name> -from 2026-10-01 -to 2026-10-31          # each project's total over the period
opendsecctl usage root -from 2026-10-01 -daily -csv > usage.csv        # per day and project, CSV
```
- Covers the project and all its subprojects: sandboxes started, sandbox-hours, CPU core-hours, memory GB-hours, GPU-hours. Per UTC day; each row counts the project's own sandboxes only, subprojects get rows of their own, and the last row is the total.
- What is counted is quota leases: all the time a sandbox holds resources, paused time included (the capacity is still its own). Running sandboxes count up to the time of the query.
- Needs `project.admin` on the project. Kept 400 days, in IAM, replicated with Raft, so node restarts and failovers lose nothing.
- Python SDK: `await client.get_usage("root/<name>", start="2026-10-01", end="2026-10-31")`.

### Entry points
- **With an LB**: the SDK uses `OPENDSEC_ADDR=<LB address>:7100`.
- **Without an LB**: the SDK uses every apiserver's address, e.g. `OPENDSEC_ADDR=10.0.0.11:7100,10.0.0.12:7100,10.0.0.13:7100`, round-robins and fails over by itself (SPEC §27.8).
- **Open to the internet**: allow only TCP 7100, and only from the callers' source addresses; the apiserver certificates must contain the public address or domain (`opendsecops certs`). Never expose any other port: IAM, watcher, edge and fleet ports, 9461–9466, 9100, 9090, 9093.
- **Moving from direct addresses to an LB**:
  1. `opendsecops certs api.opendsec.internal,<LB address>,...`;
  2. `opendsecops push-config all` and `opendsecops restart`;
  3. tell callers to switch `OPENDSEC_ADDR` to the LB;
  4. once the old addresses see no traffic, tighten the security group.

### E2B gateway (optional, SPEC §37)
Lets callers using the E2B SDK connect directly.
1. Add an `e2b` section to the cluster config and deliver it through fleet (§6.2):
   ```json
   "e2b": {
     "gateways": [{"addr": "10.0.0.11:7400"}, {"addr": "10.0.0.12:7400"}],
     "project": "root/e2b",
     "templates": {"base": {"image": "root/py:3.12", "backend": "microvm", "cpu": 2, "memory_mb": 1024}},
     "max_timeout_s": 86400
   }
   ```
2. Give machines the role, one at a time: `opendsecctl fleet node set <name> -roles <existing roles>,e2b=<index>` (the index is the position in `gateways`), then `opendsecctl fleet node sync <name>`. The node agent brings the machine to its desired release and config and enables and starts `opendsec-e2b@<index>`; once it is ready, do the next machine.
3. Put an LB in front: forward TCP 7400, health check HTTP 9467 `/readyz`, idle timeout at least 60 s (the SDK's streams send keepalives every 50 s). For HTTPS from outside, terminate TLS on the LB, or set `tls_cert` and `tls_key` in `gateways`.
4. Callers set `E2B_API_URL` and `E2B_SANDBOX_URL` to the gateway and `E2B_API_KEY` to their OpenDsec token. The token needs `sandbox.create` and `sandbox.operate` on `project` and `layer.use` on the images' project; for snapshots (`create_snapshot()`), also `layer.publish` on `project`, where snapshots are stored as images.

The gateway is stateless and calls the apiserver with each caller's own token, so permissions, quotas and audit are exactly as with the OpenDsec SDK.

**E2B code interpreter** (the `e2b_code_interpreter` package) needs a template of its own:
1. Download E2B's code-interpreter repository and build the image with `deploy/e2b/build-code-interpreter.py`. It creates a microVM, installs Jupyter and E2B's services, and takes a snapshot with memory, `root/code-interpreter:v1`. It needs internet access (pip, apt) and `layer.publish` on `root`.
2. Add `"code-interpreter-v1": {"image": "root/code-interpreter:v1", "backend": "microvm", "cpu": 2, "memory_mb": 2048}` to `e2b.templates`. `cpu` and `memory_mb` must match the snapshot.
3. Deliver the config as in §6.2. Check it with `test/e2e/testdata/e2b_code_interpreter_check.py`.

## 5. Failures

### One IAM node down
- The other two replicas keep serving. `OpenDsecIAMQuorumAtRisk` fires: **a second node must not fail now**.
- If the machine comes back: start `opendsec-iam@<id>`, and it catches up by itself.
- If it does not (a new machine with a new address), replacing replica 2 with a new replica id 3:
  ```sh
  opendsecctl iam member remove 2
  # opendsec.json: change the replicas entry with id 2 to id 3 at the new address; change the inventory to match
  opendsecops certs && opendsecops install <new node>
  echo 'OPENDSEC_IAM_FLAGS=-join' > /etc/opendsec/iam.env      # on the new node
  opendsecops start <new node>      # does not bootstrap; waits to be added. /readyz fails until then, so this step times out, as expected
  opendsecctl iam member add 3 -raft-addr <new IP>:7011 -iam-addr <new IP>:7001
  rm /etc/opendsec/iam.env       # after joining, the data directory holds Raft state and -join no longer matters
  opendsecops push-config all && opendsecops restart     # so the other components use the new address list
  ```
- If the machine keeps its address but got a new disk: start it with `-join`. It is still a member, and the leader sends it a snapshot.

### All of IAM lost (disaster recovery)
1. Empty `/var/lib/opendsec/iam` on every replica and start them. The new cluster bootstraps with the admin token.
2. `opendsecctl iam restore <latest backup>`. Backups are in `/var/backups/opendsec` on every IAM node, and in `backups/` on the ops machine.
3. After one reconciliation, sandboxes alive on the edges are registered in the quotas again.
4. Principals, tokens and projects created after the backup are lost and must be recreated.

### One compute node down
- The other nodes keep serving.
- Sandboxes on the failed machine are lost. After `lost_edge_grace` (120 s), the watcher releases their quota.
- When the machine comes back, the edge re-adopts sandboxes still running (unless the whole machine rebooted). After a reboot nothing can be re-adopted, and paused microVMs are removed too (see "Maintaining a machine").

### NAS unavailable
- Running microVMs are unaffected: they run from local copies of their images and the snapshot cache.
- Running containers are unaffected too: they use node-local copies of their layers (`layer_cache`, on by default). With `layer_cache` off, a container's read-only layers come straight from the store, and reading files not in the page cache hangs until the NAS is back (SPEC §33: a 60-second NFS outage held a command for 88 seconds).
- Operations that need the store wait until the NAS returns or their calls time out: new creations (creations waited up to 94 seconds during an outage in our tests, and all succeeded afterwards), pack, snapshot, cross-node fork.
- Alert `NodeImageStoreMissing`. NFS is mounted `hard`, so I/O that was stuck completes once the NAS is back.

### System disk
- Audit logs are in `audit_dir` (default `/var/log/opendsec/audit`), at most `audit_keep` files per apiserver (default 8 of 256 MB each). Ship them elsewhere regularly if they must be kept long.
- Every sandbox produces some kernel and networkd messages. `deploy/node/install.sh` keeps them in the journal only (which by default uses at most 10% of its file system) and turns off networkd-dispatcher, which has no scripts. Without that, `/var/log/syslog` grows by more than 1 GB a day under load (SPEC §33.2).

### Alerts and what to check

| Alert | Check first |
|---|---|
| OpenDsecComponentDown / NotReady | `opendsecops status`; on the node, `journalctl -u <unit>`. `curl <ip>:<port>/readyz` returns why it is not ready |
| OpenDsecIAMNoLeader | Are fewer than 2 replicas up; is port 7011 open between them |
| OpenDsecEdgeUnhealthy | Is the machine up, is `opendsec-edge` running |
| OpenDsecCreateErrors / CreateSlow | `opendsec_apiserver_create_seconds` by `reason` for the error mix; the edges' `opendsec_edge_create_phase_seconds` |
| OpenDsecCapacityLow / EdgeUnderPressure | Add edges, or lower project quotas |
| OpenDsecCertExpiringSoon | Renew as in §4, "Certificates" |
| OpenDsecIAMBackupStale | `systemctl status opendsec-iam-backup`; look at `/var/backups/opendsec` |
| OpenDsecSLOCreateBurnFast / BurnSlow, SLORuntimeBurnFast / BurnSlow | The error budget burns too fast ([SLO](SLO.md)): as for CreateErrors, break down by `reason` and `method` to see which errors and since when; was there a release, a config change or a node failure at the time |

Every alert: [Monitoring and alerts](MONITORING.md).

## 6. The fleet service (SPEC §28)

With many machines, upgrades and config changes are no longer pushed over ssh from the ops machine one by one: the fleet service advances them in batches, and a node agent on each machine carries them out. `opendsecops` stays for the first install, certificates, adding machines and emergencies.

### 6.1 Parts
- **`opendsec-fleet@<id>`**: three replicas on the control-plane nodes next to IAM, port 7300 (metrics 9465). The replica holding the IAM lock `fleet-controller` leads; the others forward requests to it. Desired state lives in IAM's key-value area and is backed up with IAM.
- **`opendsec-nodeagent`**: one per machine, running as root (metrics 9466). It reports to fleet every 10 seconds and carries out what fleet asks: download a release, switch releases, write `/etc/opendsec/{opendsec.json,edge.env}`, restart `opendsec-*` services. It accepts these actions only.
  - The agent runs from `/opt/opendsec/agent/opendsec-nodeagent`, which does not switch with releases; a new release's agent replaces it only after passing a `-check` self-test.
  - With all of fleet down, node agents change nothing, and components and sandboxes keep running.
- **CLI**: `opendsecctl fleet ...`, through an apiserver, needs `fleet.view` (read) or `fleet.operate` (change) on root; `project.admin` includes both. Every action is audited. With every apiserver down, connect to fleet directly from the ops machine with `-direct -fleet <replica addresses> -pki $OPENDSEC_OPS/pki -ops-id ops`.

### 6.2 Releases and upgrades
```sh
make build && deploy/prod/opendsecops release bin/      # package, with the firecracker, jailer and kernel pinned in deploy/deps.lock
opendsecctl fleet release push $OPENDSEC_OPS/releases/<version>
opendsecctl fleet rollout create -release <version>        # default: 1 canary, 5 minutes of bake, 5% per batch, 60 s between batches
opendsecctl fleet rollout status [-steps]
```
- Order: every target machine downloads the release first; control-plane nodes upgrade one by one, the IAM leader's node last; then one edge as the canary, and after its bake, the edges in batches, with at most half of a batch from any one failure domain.
- Each edge is drained before its upgrade; after it, its own `/readyz` and the watcher snapshot must be fine before scheduling resumes. Edge restarts leave existing sandboxes alone.
- Before each batch: the machines already upgraded in this rollout are still fine, and every control-plane component is ready. With `fleet.prometheus_url` and `fleet.gates` set, those PromQL queries are checked during the bake and before each batch: a value over its limit, or a query that cannot be read (Prometheus down), pauses the rollout; a query with no samples reads as 0, provided Prometheus is scraping OpenDsec at all (`fleet.gates_up`, by default some `up{job=~"opendsec-.*"}` is 1); otherwise the rollout pauses with `gate data unavailable`. Resuming a rollout a gate paused lets the gates pass until the next batch has started. Rollbacks do not check the gates.
- **When something fails**: the failed machine goes back to its old release by itself and is pinned, and the rollout pauses. Then:
  - `opendsecctl fleet rollout resume <id>`: accept the failures and upgrade the remaining machines;
  - `opendsecctl fleet rollout rollback <id>`: take the upgraded machines back to the old release in reverse order, in batches;
  - `opendsecctl fleet rollout abort <id>`: stop where it is.

  Once the cause is found, unpin with `opendsecctl fleet node unpin <name>`.
- **Config only**: `opendsecctl fleet config put opendsec.json -note ...` creates a new config generation; then `opendsecctl fleet rollout create -config-gen <generation>`. The config may not contain `service_token` or `iam.admin_token`.
- With fleet replicas, `opendsecops upgrade` and `restart` refuse to run; in an emergency, add `OPENDSEC_FORCE=1`.

### 6.3 Adding, maintaining and retiring machines
```sh
deploy/prod/opendsecops add-node n17 <ssh address> <private address> edge=n17   # certificates, install, node agent
opendsecctl fleet nodes -state pending                               # it shows up here once its agent reports
opendsecctl fleet node accept n17 -roles edge=n17 -domain az2        # deliver the current release and config and start it
```
- New edges need no entry in `edges`: `edge_template` in the cluster config covers every unlisted edge.
- Adding a role to an existing machine (e.g. `e2b`): `node set <name> -roles ...`, then `node sync <name>`, one machine at a time. Changing roles alone starts nothing; the machine is deployed at its next rollout or sync. fleet built before 2026-10-23 deadlocked rollouts when several machines got roles at once, each waiting for the other's new units (SPEC §37.7); use sync in that case.
- Maintenance: `opendsecctl fleet node cordon <name>` stops scheduling there (fleet keeps it so), and `node uncordon` after maintenance; `node evacuate <name>` cordons and then waits for every sandbox on the machine to end.
- Retiring: first `node evacuate <name>`, and once its sandboxes are gone, `opendsecctl fleet node retire <name>`: the node agent stops and disables the machine's components. fleet refuses to retire a machine not evacuated (not cordoned, or still with sandboxes); machines no longer sending heartbeats can be retired directly. Move control-plane roles off a machine first.

### 6.4 Moving from opendsecops to fleet (once, without downtime)
1. In the inventory, add `fleet=<id>` to the control-plane nodes; in `opendsec.json`, add a `fleet` section (see `deploy/prod/cluster.example.json`), and point microvm's `firecracker`, `jailer` and `kernel` at `/opt/opendsec/current/...`.
2. `opendsecops certs`: issues the fleet, node agent and ops certificates.
3. One last rolling upgrade with opendsecops (to a release with fleet and the node agent): `opendsecops release bin/`, `opendsecops push-config all`, `OPENDSEC_FORCE=1 opendsecops upgrade <version>`, then `opendsecops start all` to start the fleet replicas.
4. `opendsecops install-agent all`: start a node agent on every machine.
5. Register: `opendsecctl fleet release push $OPENDSEC_OPS/releases/<version>`; `opendsecctl fleet config put $OPENDSEC_OPS/opendsec.json`; `opendsecctl fleet import -inventory $OPENDSEC_OPS/inventory -release <version> -config-gen 1 -domain <failure domain>`.
6. `opendsecctl fleet nodes`: every machine reports, `RUNNING` matches `RELEASE`, and every `UNITS` is ready.
