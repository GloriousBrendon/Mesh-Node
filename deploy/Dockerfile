# mesh-node in seed mode (SPEC-seed D1, D11). Build from the repo root:
#   docker build -f deploy/Dockerfile .
FROM rust:1.99-trixie AS build
WORKDIR /src
COPY . .
# No `audio`: a seed makes no calls, and the image has no ALSA or CMake.
RUN cargo build --release --locked -p mesh-node --no-default-features && strip target/release/mesh-node
# An empty /data owned by the runtime user: a new named volume copies it, so
# the seed can write its key without root.
RUN mkdir /data

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /src/target/release/mesh-node /mesh-node
COPY --from=build --chown=65532:65532 /data /data
USER nonroot
VOLUME /data
ENTRYPOINT ["/mesh-node", "seed", "--data", "/data"]
