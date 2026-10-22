# Mesh-Node

Mesh's networking engine (private). One Rust binary that runs two ways:

- as the helper Mesh-Voice drives over stdio (JSON lines, like `mesh-wa` and
  `mesh-dc`);
- headless, as an always-on seed node (later).

Planning, specs and docs live in Mesh-Voice under `design/mesh/`.

## Build and test

```sh
cargo build --release          # target/release/mesh-node
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

## Layout

- `crates/mesh-identity`: keys and IDs, devices, the password keystore, friend
  codes, safety numbers, device linking.
- `crates/mesh-node`: the binary.
