//! Shared by the process tests.

/// A plain-http relay on loopback, which `--relay` allows: no internet
/// needed, and nothing in the helper has to trust a self-signed relay.
pub struct Relay {
    pub url: String,
    // Runs the server; dropping it stops the relay.
    pub runtime: tokio::runtime::Runtime,
}

impl Relay {
    pub fn start() -> Self {
        use iroh_relay::server::{RelayConfig, Server, ServerConfig};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let url = runtime.block_on(async {
            let mut config = ServerConfig::default();
            config.relay = Some(RelayConfig::new((std::net::Ipv4Addr::LOCALHOST, 0)));
            let server = Server::spawn(config).await.unwrap();
            let url = format!("http://{}", server.http_addr().unwrap());
            // The server stops when dropped; the runtime outlives the test.
            std::mem::forget(server);
            url
        });
        Self { url, runtime }
    }
}
