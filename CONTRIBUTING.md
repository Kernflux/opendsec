# Contributing

Issues and pull requests are welcome, in English or Chinese.

- Build and test: `make build`, `make test` (Go 1.27+). Tests that need
  root, KVM or a guest kernel skip without them; run them on a KVM machine
  as root before touching a backend (see the README's "Develop").
- The VM tests (`internal/edge/backend/microvm`, `fullvm`, parts of
  `test/e2e`) need root, `/dev/kvm`, Firecracker and jailer on PATH, and
  guest kernels:
  ```sh
  OPENDSEC_TEST_STATE=/data/t \
  OPENDSEC_FC_KERNEL=<a Firecracker CI kernel> \
  OPENDSEC_FC_OPENDSEC_KERNEL=<deploy/guest-kernel build> \
  OPENDSEC_FC_EROFS_KERNEL=<a build with EROFS, e.g. the .2 one> \
  go test ./internal/edge/backend/microvm/ ./test/e2e/
  ```
  Keep `OPENDSEC_TEST_STATE` short: the VMs' unix sockets live under it,
  and a socket path over 108 bytes fails with `connect: invalid argument`
  (the default, under `$TMPDIR`, is often too long).
  `OPENDSEC_TEST_XSTATE` points the reflink tests at an XFS directory;
  `OPENDSEC_BENCH=1` runs the benchmarks.
- `govulncheck ./...` must report nothing (the `vuln` workflow runs it on
  every change and weekly).
- Format with `gofmt`; `go vet ./...` must pass.
- After editing `proto/`, run `make proto` and commit the generated code
  (Go in `gen/`, Python in `sdk/python/opendsec/_pb`, generated with
  grpcio-tools 1.73.1).
- Design changes: describe them in `docs/SPEC.md` in the same change, with
  measurements when the change is about performance.
- One logical change per pull request, with a commit message that says
  why.

## Contributor License Agreement

Before we can merge your first pull request, you need to sign the
[Contributor License Agreement](CLA.md); a bot asks you to on the pull
request, and signing takes one comment. You keep the copyright of your
contribution. The CLA lets Yibo Zhou license it under the project's
licenses (AGPL-3.0, and Apache-2.0 for the client parts, see NOTICE) and
also under the commercial license, which funds the project's development.
