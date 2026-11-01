FROM rust:1.99.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

# Official XTLS image, pinned to a multi-architecture OCI manifest digest.
FROM ghcr.io/xtls/xray-core:26.10.21@sha256:d5c3729dfeed7c412af17a63b941c48c76ba68afee5b6184fe4078f8fa8bedcc AS xray

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=xray /usr/local/share/xray /usr/local/share/xray
COPY --from=build /build/target/release/proxy-signal /usr/local/bin/proxy-signal
ENV XRAY_LOCATION_ASSET=/usr/local/share/xray
RUN install -d -m 0700 -o 65532 -g 65532 /data
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/proxy-signal"]
CMD ["/etc/proxy-signal/config.yaml"]
