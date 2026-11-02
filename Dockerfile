# Build + test Akkoro inside Linux containers (Docker).
# Two containers each run `akkoro`, get a TUN device, and ping each other's
# inner IP through the encrypted tunnel.

# ---- build stage ----
FROM rust:1.98-slim AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/akkoro /usr/local/bin/akkoro
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
