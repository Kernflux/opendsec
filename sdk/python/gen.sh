#!/bin/sh
# Regenerate the protobuf/gRPC stubs used by opendsec from ../../proto.
set -e
cd "$(dirname "$0")"
# Generate with grpcio-tools 1.73.x: the code then needs grpcio>=1.73.1 and
# protobuf>=6.31 (pyproject), which the cloud pypi mirror has; newer
# tools raise both floors.
PY=${PY:-.venv/bin/python}
OUT=opendsec/_pb
rm -rf "$OUT" && mkdir -p "$OUT"
$PY -m grpc_tools.protoc -I ../../proto --python_out="$OUT" --grpc_python_out="$OUT" ../../proto/opendsec/v1/*.proto
# Generated code imports "opendsec.v1"; make it relative to this package.
sed -i 's/^from opendsec\.v1 import/from opendsec._pb.opendsec.v1 import/' "$OUT"/opendsec/v1/*.py
touch "$OUT/__init__.py" "$OUT/opendsec/__init__.py" "$OUT/opendsec/v1/__init__.py"
