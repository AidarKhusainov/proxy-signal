FROM rust:1.99.1-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Official XTLS image, pinned to a multi-architecture OCI manifest digest.
FROM ghcr.io/xtls/xray-core:26.10.21@sha256:d5c3729dfeed7c412af17a63b941c48c76ba68afee5b6184fe4078f8fa8bedcc AS xray

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
# Copy the trust store from the pinned build image instead of mutable apt packages.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=xray /usr/local/share/xray /usr/local/share/xray
COPY --from=build /build/target/release/proxy-signal /usr/local/bin/proxy-signal
ENV XRAY_LOCATION_ASSET=/usr/local/share/xray
RUN install -d -m 0755 /etc/proxy-signal /profiles \
    && install -d -m 0700 -o 65532 -g 65532 /data
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/proxy-signal"]
CMD ["/etc/proxy-signal/config.yaml"]
