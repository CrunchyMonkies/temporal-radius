# syntax=docker/dockerfile:1.7
#
# Multi-arch build of a fully static (musl) radius-coa-worker in a FROM scratch image.
# The builder always runs natively on the build host and cross-compiles with cargo-zigbuild,
# so `--platform linux/amd64,linux/arm64` needs no QEMU emulation.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/radius-coa-worker:<tag> --push .

FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/cargo-zigbuild:0.20 AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler libprotobuf-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ARG RUST_VERSION=1.94
RUN rustup toolchain install "$RUST_VERSION" --profile minimal \
      --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl \
 && rustup default "$RUST_VERSION"
WORKDIR /src

ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac > /rust-target

# Dependency layer: build against a stub main so source edits don't rebuild every crate.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo zigbuild --release --locked --target "$(cat /rust-target)" \
 && rm -rf src

COPY dictionary ./dictionary
COPY src ./src
RUN touch src/main.rs \
 && cargo zigbuild --release --locked --target "$(cat /rust-target)" \
 && cp "target/$(cat /rust-target)/release/radius-coa-worker" /radius-coa-worker

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /radius-coa-worker /radius-coa-worker
USER 65534:65534
EXPOSE 8080
# Exec form needs no shell: the binary probes its own /readyz endpoint (HEALTH_BIND, default :8080).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/radius-coa-worker", "healthcheck"]
ENTRYPOINT ["/radius-coa-worker"]
CMD ["worker"]
