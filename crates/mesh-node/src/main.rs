//! `mesh-node`: Mesh's networking engine. For now it only reports its version;
//! helper mode (JSON lines on stdio, like mesh-wa and mesh-dc) comes next.

fn main() {
    println!("mesh-node {}", env!("CARGO_PKG_VERSION"));
}
