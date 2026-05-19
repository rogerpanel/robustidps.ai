# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the RobustIDPS.ai Rust agent binaries.
#
#   Stage `builder` — compile all five crates against system clang +
#                     libbpf-dev + libpcap-dev + pahole.
#   Stage `runtime` — slim Debian 12 with just the libraries the
#                     binaries dlopen at runtime, plus the binaries.
#
# Final image is ~120 MB. Multi-arch via TARGETPLATFORM (amd64 / arm64).
#
# Usage:
#   docker buildx build --platform linux/amd64 -t robustidps/agent:latest \
#     -f agent/Dockerfile agent/
#
# The XDP binary in a container needs --cap-add=NET_ADMIN --cap-add=BPF
# --cap-add=PERFMON and access to /sys/fs/bpf — see deploy/systemd/ for
# the native-host install which is the recommended deployment model.
# This Dockerfile is mostly useful for CI smoke-tests + portability work.

ARG RUST_VERSION=1.95
ARG DEBIAN_VERSION=bookworm

# ╭─────────────────────────────────────────────────────────────────╮
# │ Stage 1: builder                                                 │
# ╰─────────────────────────────────────────────────────────────────╯
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

# Build deps — clang + LLVM + libbpf headers + pcap + protoc + pahole.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev \
        gcc-multilib \
        dwarves \
        libpcap-dev \
        protobuf-compiler \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pre-cache the cargo registry / dep compilation.
WORKDIR /build

# Copy the workspace manifest + every crate manifest first so deps cache
# survives source-only changes.
COPY Cargo.toml Cargo.lock ./
COPY agent-features/Cargo.toml      agent-features/
COPY agent-cli/Cargo.toml           agent-cli/
COPY agent-netfilter/Cargo.toml     agent-netfilter/
COPY agent-edge/Cargo.toml          agent-edge/
COPY agent-edge/build.rs            agent-edge/
COPY agent-edge/proto/              agent-edge/proto/
COPY agent-inference/Cargo.toml     agent-inference/
COPY agent-xdp/Cargo.toml           agent-xdp/
COPY agent-xdp/build.rs             agent-xdp/
COPY agent-xdp/bpf/                 agent-xdp/bpf/

# Dummy `main.rs`/`lib.rs` per crate so cargo can resolve deps + build
# them without the real sources. Wiped before the real build below.
RUN set -eux; \
    for crate in agent-features agent-cli agent-netfilter agent-edge agent-inference agent-xdp; do \
        mkdir -p "$crate/src"; \
        if grep -q '^\[\[bin\]\]' "$crate/Cargo.toml" 2>/dev/null; then \
            echo 'fn main(){}' > "$crate/src/main.rs"; \
        fi; \
        if grep -q '^\[lib\]' "$crate/Cargo.toml" 2>/dev/null; then \
            echo '' > "$crate/src/lib.rs"; \
        fi; \
        [ -f "$crate/src/lib.rs" ] || echo '' > "$crate/src/lib.rs"; \
        [ -f "$crate/src/main.rs" ] || echo 'fn main(){}' > "$crate/src/main.rs"; \
    done

# Warm the dep cache. `agent-edge --features onnx` pulls the ort crate
# which is the heaviest dep; building once primes the layer for re-use.
RUN cargo build --release --workspace --features agent-edge/onnx 2>&1 \
    | tail -3 || true

# Now blow away the dummy sources and copy in the real ones.
RUN find . -path './target' -prune -o \
    \( -name '*.rs' -path '*/src/*' -delete \) -print 2>/dev/null \
    | head -5

COPY agent-features/  agent-features/
COPY agent-cli/       agent-cli/
COPY agent-netfilter/ agent-netfilter/
COPY agent-edge/      agent-edge/
COPY agent-inference/ agent-inference/
COPY agent-xdp/       agent-xdp/

# Real build. Touch the build.rs files so they re-run with the actual
# source. ONNX feature is on so the daemon can hot-swap models.
RUN touch agent-edge/build.rs agent-xdp/build.rs && \
    cargo build --release --workspace --features agent-edge/onnx 2>&1 \
    | tail -3

# Sanity-check the artefacts exist where we expect them.
RUN ls -la target/release/robustidps-agent \
            target/release/robustidps-netfilter \
            target/release/robustidps-edge \
            target/release/robustidps-xdp

# ╭─────────────────────────────────────────────────────────────────╮
# │ Stage 2: runtime                                                 │
# ╰─────────────────────────────────────────────────────────────────╯
FROM debian:${DEBIAN_VERSION}-slim AS runtime

# Runtime deps:
#   - libpcap0.8 : agent-features + agent-edge live capture
#   - libonnxruntime + libssl3 : agent-edge --features onnx loads
#       libonnxruntime.so.* dynamically; only needed if the deploy plans
#       to use the ONNX classifier.
#   - iptables / nftables : agent-netfilter's runtime exec targets
#   - ca-certificates : gRPC TLS handshakes (when wired in step 6)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        libssl3 \
        iptables \
        nftables \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# libonnxruntime is not in Debian's main repo — install via tarball.
# Pin the version against `agent-inference/Cargo.toml`'s ort pin.
ARG ORT_VERSION=1.20.1
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) ORT_ARCH=x64 ;; \
        arm64) ORT_ARCH=aarch64 ;; \
        *) echo "Unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-${ORT_ARCH}-${ORT_VERSION}.tgz" \
        -o /tmp/ort.tgz; \
    tar -xzf /tmp/ort.tgz -C /opt; \
    mv "/opt/onnxruntime-linux-${ORT_ARCH}-${ORT_VERSION}" /opt/onnxruntime; \
    rm /tmp/ort.tgz; \
    ldconfig /opt/onnxruntime/lib

ENV LD_LIBRARY_PATH=/opt/onnxruntime/lib

# Non-root runtime user.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin robustidps

# Copy binaries (root-owned, world-executable).
COPY --from=builder \
    /build/target/release/robustidps-agent \
    /build/target/release/robustidps-netfilter \
    /build/target/release/robustidps-edge \
    /build/target/release/robustidps-xdp \
    /usr/local/bin/

RUN install -d -m 0755 -o robustidps -g robustidps \
    /var/lib/robustidps/edge/models \
    /etc/robustidps

# Default command runs the edge daemon. Override with `docker run … \
# /usr/local/bin/robustidps-xdp …` for the XDP variant.
USER robustidps
WORKDIR /var/lib/robustidps
ENTRYPOINT ["tini", "--", "/usr/local/bin/robustidps-edge"]
CMD ["--help"]

# Bake some labels for image-introspection.
LABEL org.opencontainers.image.title="robustidps-agent"
LABEL org.opencontainers.image.source="https://github.com/rogerpanel/robustidps.ai"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.description="RobustIDPS.ai Rust edge-agent binaries (agent + netfilter + edge + xdp). Native-host systemd deploy under deploy/systemd/ is the recommended production path; this image is for CI + portability tests."
