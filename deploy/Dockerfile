# One image with every OpenDsec binary. Build from the repository root:
#   docker build -f deploy/Dockerfile -t opendsec:0.1.0 .
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static binaries: opendsec-aether / opendsec-chronus are bind-mounted into arbitrary sandbox rootfs.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

FROM debian:bookworm-slim
# e2fsprogs: mkfs.ext4 for sandbox writable disks (edge); util-linux: mount/losetup for debugging.
RUN apt-get update && apt-get install -y --no-install-recommends e2fsprogs util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/opendsec-iam /out/opendsec-watcher /out/opendsec-apiserver /out/opendsec-edge /out/opendsecctl /usr/local/bin/
# In-sandbox agents live in a versioned directory; edges point agent_dir at it,
# so upgrading never swaps agents under running sandboxes.
COPY --from=build /out/opendsec-aether /out/opendsec-chronus /opt/opendsec/agents/0.1.0/
ENTRYPOINT ["/usr/local/bin/opendsecctl"]
