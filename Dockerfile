# Build a fully static binary against musl libc using the alpine-based Rust image.
# The default target on rust:*-alpine is x86_64-unknown-linux-musl, so no cross-compilation
# is needed; the resulting binary is statically linked against musl out of the box.
FROM rust:1.95.0-alpine3.23 AS builder
RUN apk add --no-cache musl-dev
WORKDIR /usr/src/cloudflare-access-forwardauth

# Pre-fetch and pre-build dependencies so Docker can cache this layer separately from the
# source code. We seed the project with a stub main.rs, build only the deps, and then drop
# the stub before copying the real source in below.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/cloudflare-access-forwardauth* target/release/deps/cloudflare_access_forwardauth*

# Build the actual binary.
COPY src ./src
RUN cargo install --locked --path .

# The binary is fully static (musl + rustls/webpki-roots), so we don't need a libc, root
# CA bundle, or anything else in the runtime image.
FROM scratch
COPY --from=builder /usr/local/cargo/bin/cloudflare-access-forwardauth /
USER 1000
ENTRYPOINT ["/cloudflare-access-forwardauth"]
