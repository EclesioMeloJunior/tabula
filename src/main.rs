#![feature(array_chunks)]

mod config;
mod crypto;
mod network;
mod trie;

use config::parser::{ConfigTOMLParser, RawChainSpecJSONParser};
use std::error::Error;
use trie::{key::Key, Trie, V0};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");

    let server_settings = config::from_file::<ConfigTOMLParser>(String::from("./config/wnd.toml"));
    let chainspec = config::from_file::<RawChainSpecJSONParser>(server_settings.chain_spec);

    let mut t = Trie::<crypto::hasher::Blake256Hasher>::new();
    for (k, v) in &chainspec.genesis.raw.top {
        let key = hex::decode(k.strip_prefix("0x").unwrap())?;
        let key = Key::new(&key);

        let value = hex::decode(v.strip_prefix("0x").unwrap())?;
        let value = Some(value);

        t.insert(key, value).unwrap();
    }

    let expected =
        hex_literal::hex!("7e92439a94f79671f9cade9dff96a094519b9001a7432244d46ab644bb6f746f");
    let root = t.root_hash(V0);

    println!("{:x?}", root);
    assert_eq!(root, expected);

    //let node = Node::new(&chainspec);
    //let gen_hash = node.storage.genesis_hash();

    //network::build_network(server_settings);

    //println!("{}", gen_hash);
    Ok(())
}
