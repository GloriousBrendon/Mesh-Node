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
- `crates/mesh-e2ee`: end-to-end encryption: e2ee bundles, 1:1 sessions and
  sender chains (vodozemac), the sealed envelope, its store.
- `crates/mesh-node`: the binary.

## License

Copyright (C) 2026 GloriousBrendon

Mesh-Node is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. See [LICENSE](LICENSE). Contributions: see
[CONTRIBUTING.md](CONTRIBUTING.md).
