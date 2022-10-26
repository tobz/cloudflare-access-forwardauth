FROM rust:1.64.0-alpine3.16 AS builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apk add -U --no-cache make autoconf g++ openssl-dev ca-certificates
RUN cargo new cloudflare-access-forwardauth
WORKDIR /usr/src/cloudflare-access-forwardauth
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo install --target x86_64-unknown-linux-musl --features static-build --path .

FROM scratch
WORKDIR /
COPY --from=builder /usr/local/cargo/bin/cloudflare-access-forwardauth .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
USER 1000
CMD ["./cloudflare-access-forwardauth"]