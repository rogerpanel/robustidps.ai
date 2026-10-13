#!/usr/bin/env bash
# edge_proto_gen.sh — generate Python gRPC stubs for the RobustIDPS edge agent.
#
# Reads agent/agent-edge/proto/edge.proto and writes:
#   backend/proto/__init__.py
#   backend/proto/edge_pb2.py
#   backend/proto/edge_pb2_grpc.py
#
# The generated edge_pb2_grpc.py is patched to use a relative import for
# edge_pb2, so it works when imported as `backend.proto.edge_pb2_grpc`.
#
# Usage:
#   ./backend/edge_proto_gen.sh          # from repo root
#   backend/edge_proto_gen.sh            # same thing
#   /abs/path/backend/edge_proto_gen.sh  # works from anywhere

set -euo pipefail

# Resolve the directory this script lives in, regardless of how it was
# invoked. backend/ is one level above the script's parent? No — the
# script *is* in backend/, so SCRIPT_DIR == backend/.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"

PROTO_FILE="${REPO_ROOT}/agent/agent-edge/proto/edge.proto"
PROTO_DIR="${REPO_ROOT}/agent/agent-edge/proto"
OUT_DIR="${SCRIPT_DIR}/proto"

if [[ ! -f "${PROTO_FILE}" ]]; then
  echo "error: proto file not found at ${PROTO_FILE}" >&2
  exit 1
fi

# Verify grpc_tools is available.
if ! python3 -c "import grpc_tools.protoc" >/dev/null 2>&1; then
  echo "error: grpc_tools.protoc is not importable." >&2
  echo "hint:  pip install grpcio-tools" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
: > "${OUT_DIR}/__init__.py"

echo "generating Python gRPC stubs from ${PROTO_FILE}"
python3 -m grpc_tools.protoc \
  -I"${PROTO_DIR}" \
  --python_out="${OUT_DIR}" \
  --grpc_python_out="${OUT_DIR}" \
  "${PROTO_FILE}"

# Patch the generated grpc stub to use a relative import so the package
# works when imported as backend.proto.edge_pb2_grpc.
GRPC_STUB="${OUT_DIR}/edge_pb2_grpc.py"
if [[ -f "${GRPC_STUB}" ]]; then
  sed -i 's/^import edge_pb2 as/from . import edge_pb2 as/' "${GRPC_STUB}"
  echo "patched ${GRPC_STUB} to use relative import for edge_pb2"
else
  echo "warning: ${GRPC_STUB} not found after generation" >&2
fi

echo "ok — stubs written to ${OUT_DIR}"
