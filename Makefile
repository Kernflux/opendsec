export PATH := $(PATH):/usr/local/go/bin:/usr/local/protoc/bin:$(HOME)/go/bin
PROTOS := $(wildcard proto/opendsec/v1/*.proto)
# E2B's envd API, served by the E2B gateway (spec §37); needs protoc-gen-connect-go.
E2B_PROTOS := $(wildcard proto/e2b/envd/*/*.proto)

.PHONY: proto build build-ee check-open test bench pysdk pytest
proto: pysdk
	protoc -I proto --go_out=. --go_opt=module=github.com/kernflux/opendsec --go-grpc_out=. --go-grpc_opt=module=github.com/kernflux/opendsec $(PROTOS)
	protoc -I proto --go_out=. --go_opt=module=github.com/kernflux/opendsec --connect-go_out=. --connect-go_opt=module=github.com/kernflux/opendsec $(E2B_PROTOS)

VERSION ?= $(shell cat VERSION 2>/dev/null || echo dev)-$(shell date -u +%Y%m%d%H%M)
VERSION := $(VERSION)

# Static binaries: opendsec-aether / opendsec-chronus run inside arbitrary sandbox rootfs.
build:
	CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/kernflux/opendsec/internal/metrics.Version=$(VERSION)" -o bin/ ./cmd/...

# Enterprise edition (ee/README.md): the open build, then ee/cmd's builds of
# the components, which replace the open ones in bin/.
build-ee: build
	CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/kernflux/opendsec/internal/metrics.Version=$(VERSION) -X github.com/kernflux/opendsec/ee/license.PublicKey=$(OPENDSEC_LICENSE_PUBKEY)" -o bin/ ./ee/cmd/...

# The open-source build must not depend on ee/ or docs/private/ (the public
# repository has neither): build and vet a copy of the tree without them.
check-open:
	d=$$(mktemp -d) && trap 'rm -rf "$$d"' EXIT && \
	git ls-files -z --cached --others --exclude-standard | grep -zv -e '^ee/' -e '^docs/private/' | xargs -0 cp --parents -t "$$d" && \
	cd "$$d" && go build ./... && go vet ./... && echo "open build ok without ee/"

test:
	go test ./...

bench: build
	./bin/opendsecctl bench -compare

pysdk:
	cd sdk/python && ./gen.sh

pytest: build
	cd sdk/python && .venv/bin/python -m pytest -q tests
