mod state;
use crate::{
    config::{genesis::RawChainSpec, ServerConfig},
    trie::V0,
};
use state::State;

struct Client {
    state: State,
}

pub fn start_client_from_genesis(server_settings: ServerConfig, chain_spec: RawChainSpec) {
    let state = State::from_genesis(chain_spec.genesis);
    println!(
        "genesis state root: {}",
        hex::encode(state.trie.root_hash(V0))
    );

    let client = Client { state };
}
