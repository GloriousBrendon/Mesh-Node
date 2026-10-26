# iroh's own relay server, the version Mesh's client uses (SPEC-seed D3).
FROM rust:1.99-trixie AS build
RUN cargo install iroh-relay@1.4.1 --features server --locked --root /out

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /out/bin/iroh-relay /iroh-relay
COPY deploy/relay.toml /relay.toml
USER nonroot
EXPOSE 3340
ENTRYPOINT ["/iroh-relay", "--config-path", "/relay.toml"]
