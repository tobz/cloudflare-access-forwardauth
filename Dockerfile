FROM rust:1.64.0-alpine3.16 AS builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apk add make autoconf g++ openssl-dev
RUN cargo new cloudflare-access-forwardauth
WORKDIR /usr/src/cloudflare-access-forwardauth
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo install --target x86_64-unknown-linux-musl --features static-build --path .

FROM scratch
COPY --from=builder /usr/local/cargo/bin/cloudflare-access-forwardauth .
USER 1000
CMD ["./cloudflare-access-forwardauth"]