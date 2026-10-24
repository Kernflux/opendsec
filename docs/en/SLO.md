# OpenDsec service level objectives (SLO)

This document defines what an OpenDsec cluster promises its callers, how that is measured, and what to do when it is missed. The targets are suggested starting points; operators can adjust them to their needs, but must then change the numbers in the `opendsec-slo` group of `deploy/monitoring/alerts.yml` to match.

Measurements are recorded in SPEC §33 (Chinese): fault injection and a 48-hour stability test.

## 1. Indicators (SLIs)

| SLI | Good events | All events | Source |
|---|---|---|---|
| Creation availability | Successful creations | All creations, minus the callers' own errors | apiserver `opendsec_apiserver_create_seconds_count` |
| Creation latency | Successful creations finished within the threshold | Successful creations | apiserver `opendsec_apiserver_create_seconds_bucket` |
| Runtime availability | Successful Exec, ExecStream, ReadFile, WriteFile and lifecycle calls (Stop, Pause, Resume, Fork) | The same, minus the callers' own errors | apiserver `opendsec_rpc_server_handled_total` |
| End-to-end success | A complete caller cycle succeeds | All cycles | the caller: `sdk/python/examples/soak.py` |

**How errors are classified**:
- **Callers' errors**: `invalid`, `unauthenticated`, `forbidden`, `not_found`, `quota_exceeded`, `rate_limited`, `conflict`. These are the caller's problem and are left out of the SLIs.
- **Server errors** count as bad events:
  - in both kinds of SLI: `unavailable`, `internal`;
  - in creation only: `timeout` (waiting for a creation slot or for the rate limiter until timing out) and `no_capacity` (insufficient capacity planning, also the server side's responsibility);
  - `timeout` in runtime calls does not count: it is mostly the caller's own timeout, or a command that has not finished.

**Server-side versus caller-side indicators**: the server counts every attempt, and the SDK retries `unavailable`, so one fault may be several failures on the server side while the caller only sees a slowdown. The caller's end-to-end success rate is what finally counts; the server-side indicators are for alerting and diagnosis.

## 2. Objectives

Over a rolling 30-day window.

| SLI | Objective | 30-day error budget |
|---|---|---|
| Creation availability | 99.9% | 0.1%: 1000 failures per million creations |
| Creation latency (container) | 99% within 5 s | 1% |
| Creation latency (microvm) | 99% within 3 s | 1% |
| Runtime availability | 99.95% | 0.05% |
| End-to-end success (`soak.py`) | 99.9% | 0.1% |

**Assumptions**:
- no more than 70% of the cluster's memory is allocated;
- fewer than 3000 containers per edge.

  Beyond these, creations slow down noticeably, because the kernel serializes `pivot_root` (SPEC §32); the latency objectives no longer apply, and the cluster should grow first.

**Behaviour under single failures** (verified by fault injection, SPEC §33):

| Failure | Promise |
|---|---|
| Any component process crashes or restarts (IAM, apiserver, watcher, edge, fleet, nodeagent) | Callers see no failures; calls may slow down, for at most 60 s |
| One control-plane node is cut off from the others | Callers see no failures |
| An edge process hangs or crashes | Its sandboxes keep running and can be operated again once the edge is back |
| 2 of 3 IAM replicas unavailable | Failures allowed: creation and login need an IAM majority; back to normal within 60 s of recovery |
| An edge node loses its network or fails entirely | Failures allowed: operations on its sandboxes fail, and on a machine failure those sandboxes are lost, as designed; new creations are unaffected and go to other nodes |
| The image store (NFS) is unreachable | Running sandboxes are unaffected (containers use local copies of their layers, `layer_cache`). New creations may fail: they wait until the store is back and fail if the outage outlasts their call timeout |
| An edge process hangs | Creations sent to it move to another edge after about 15 s; operations on its sandboxes wait for it to recover |

**Not covered by the SLOs**:
- failures of the callers' own programs in their sandboxes;
- sandboxes lost to a node reboot (by design; see the operations manual §5);
- image import times.

## 3. Measuring

**Server side**: the Prometheus rules are in the `opendsec-slo` group of `deploy/monitoring/alerts.yml`:
- recording rules such as `opendsec:create_availability:ratio_rate5m`;
- two burn-rate alerts (multi-window, multi-burn-rate, as in the Google SRE workbook):

  | Alert | Condition | Meaning |
  |---|---|---|
  | `OpenDsecSLOCreateBurnFast` | Error rates over 1 hour and over 5 minutes both above 14.4 times the budget | At this rate, 2 days spend the 30-day budget |
  | `OpenDsecSLOCreateBurnSlow` | Error rates over 6 hours and over 30 minutes both above 6 times the budget | At this rate, 5 days spend the budget |

  Runtime availability has the same two.

Availability over the past 30 days in Prometheus:
```promql
1 - sum(increase(opendsec_apiserver_create_seconds_count{reason=~"unavailable|internal|timeout|no_capacity"}[30d]))
  / sum(increase(opendsec_apiserver_create_seconds_count{reason!~"invalid|unauthenticated|forbidden|not_found|quota_exceeded|rate_limited|conflict"}[30d]))
```

**Caller side**: run `soak.py` for a long time with a caller's onboarding bundle, then summarize with `soak_report.py`, per hour or per period:
```sh
python soak.py 172800 8 soak.csv     # 48 hours, concurrency 8
python soak_report.py soak.csv
```
Run `load_test.py` or `soak.py` with every release and config change and check the failure count (operations manual §4).

## 4. When the error budget runs out

- **Less than half the budget left**: hold non-urgent releases and config changes, and find where the errors come from first.
- **Budget spent**:
  - only changes that improve stability, each with a load test;
  - write the cause and the improvements into an incident record.
- **A burn-rate alert fires**: follow the operations manual §5. Start with `opendsec_apiserver_create_seconds_count` grouped by `reason`, then the edges' `opendsec_edge_rejected_total`.
