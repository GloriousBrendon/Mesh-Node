//! A plain-http relay on loopback, as the process tests use, for Mesh-Voice's
//! tests to run beside `mesh-node`: prints its URL, then serves until stdin
//! closes. Test use only; it isn't part of the shipped binary.
//!
//! `cargo build -p mesh-node --example test_relay`

use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use std::io::Read;

#[tokio::main]
async fn main() {
    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new((std::net::Ipv4Addr::LOCALHOST, 0)));
    let server = Server::spawn(config).await.expect("the relay didn't start");
    println!("http://{}", server.http_addr().expect("an http address"));
    // Until whoever started it goes away.
    tokio::task::spawn_blocking(|| std::io::stdin().read_to_end(&mut Vec::new()))
        .await
        .ok();
    drop(server);
}
