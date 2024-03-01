#![feature(array_chunks)]
#![feature(associated_type_defaults)]

mod config;
mod core;
mod crypto;
mod network;
mod trie;

use config::parser::{ConfigTOMLParser, RawChainSpecJSONParser};
use std::error::Error;
use trie::{key::Key, traits::Storage, Trie, V0};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_settings = config::from_file::<ConfigTOMLParser>(String::from("./config/wnd.toml"));
    let chainspec = config::from_file::<RawChainSpecJSONParser>(server_settings.clone().chain_spec);

    core::start_client_from_genesis(server_settings, chainspec.clone());

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
    let root = t.root_hash(V0).unwrap();

    assert_eq!(root, expected);
    Ok(())
}
