use libp2p::{noise, ping, tcp, yamux};
use libp2p::{Multiaddr, SwarmBuilder};
use std::error::Error;
use std::time::Duration;

use crate::config;

pub fn build_network(cfg: config::ServerConfig) -> Result<(), Box<dyn Error>> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| ping::Behaviour::default())?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    for bootnode in cfg.bootnodes {
        let remote: Multiaddr = bootnode.parse()?;
        swarm.dial(remote)?
    }

    Ok(())
}
