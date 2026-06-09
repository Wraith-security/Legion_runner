# syntax=docker/dockerfile:1
#
# Legion Runner — Chainguard Wolfi image.
#
# Wolfi is glibc-based (not musl), so GitHub Actions' injected node runs cleanly
# when this image is used as a job `container:` — the reason we prefer it over
# Alpine. The image carries everything both the ephemeral runner host and the
# Legion Harden Runner action need: the `legionr` binary, Node, and the network
# tooling for egress monitoring/blocking.

# ── Stage 1: build the legionr control plane on Wolfi ────────────────────────
FROM cgr.dev/chainguard/wolfi-base AS build
RUN apk add --no-cache build-base rust
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p legionr-cli \
    && strip target/release/legionr

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/wolfi-base AS runtime

# nodejs        → runs the Harden Runner action (and GitHub's node actions)
# iproute2      → `ss` for egress sampling
# iptables      → block-mode default-deny egress
# git/curl/tar  → the official GitHub Actions runner
# bash          → install/harden scripts
LABEL org.opencontainers.image.title="Legion Runner" \
      org.opencontainers.image.description="Hardened, ephemeral, single-use GitHub Actions runner + Harden Runner action" \
      org.opencontainers.image.source="https://github.com/OpenSource-For-Freedom/legion_runner" \
      org.opencontainers.image.licenses="MIT"

# Note: `tar` is provided by busybox in wolfi-base (no separate package).
RUN apk add --no-cache \
        nodejs \
        bash \
        iproute2 \
        iptables \
        git \
        curl \
        ca-certificates-bundle \
        libgcc \
    && addgroup -S legionr \
    && adduser -S -G legionr -h /opt/legion-runner legionr \
    && mkdir -p /opt/legion-runner/_work /etc/legion-runner \
    && chown -R legionr:legionr /opt/legion-runner

COPY --from=build /src/target/release/legionr /usr/local/bin/legionr
COPY action  /opt/legion-runner/action
COPY scripts /opt/legion-runner/scripts
COPY systemd /opt/legion-runner/systemd

ENV PATH="/usr/local/bin:${PATH}" \
    LEGIONR_DATA_DIR="/opt/legion-runner"

# Default to the non-root service user for standalone `docker run`. Note: when
# used as an Actions `container:`, GitHub overrides the entrypoint and may run
# as root for workspace setup — that's expected and fine.
USER legionr
WORKDIR /opt/legion-runner
ENTRYPOINT ["/usr/local/bin/legionr"]
CMD ["--help"]
