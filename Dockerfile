# Configure our Rust build environment, targetting MUSL for an entirely statically-linked binary.
FROM rust:1.64.0-alpine3.16 AS builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apk add -U --no-cache make autoconf g++ openssl-dev ca-certificates
RUN cargo new cloudflare-access-forwardauth
WORKDIR /usr/src/cloudflare-access-forwardauth

# Copy over our Cargo.toml/Cargo.lock file so we can pre-fetch our dependencies. Doing this
# individually also should let us take advantage of layer caching, since fetching the crates.io
# registry index the first time is very slow. We have to add a dummy main.rs to allow Cargo to
# actually do its thing.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && touch src/main.rs && cargo fetch

# Now copy over our actual source and build the binary in statically-linked mode.
COPY src ./src
RUN cargo install --target x86_64-unknown-linux-musl --features static-build --path .

# Copy over the built binary, and TLS root certificates, to our final image.
FROM scratch
WORKDIR /
COPY --from=builder /usr/local/cargo/bin/cloudflare-access-forwardauth .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 1000
CMD ["./cloudflare-access-forwardauth"]