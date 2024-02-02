#![feature(array_chunks)]

mod config;
mod crypto;
mod network;
mod trie;

use config::parser::{ConfigTOMLParser, RawChainSpecJSONParser};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");

    let server_settings = config::from_file::<ConfigTOMLParser>(String::from("./config/wnd.toml"));
    let chainspec = config::from_file::<RawChainSpecJSONParser>(server_settings.chain_spec);

    //let node = Node::new(&chainspec);
    //let gen_hash = node.storage.genesis_hash();

    //network::build_network(server_settings);

    //println!("{}", gen_hash);
    Ok(())
}
