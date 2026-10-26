FROM rust:1.99-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p pact-refd

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 pactref
COPY --from=builder /src/target/release/pact-refd /usr/local/bin/refd
USER pactref
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/refd"]
