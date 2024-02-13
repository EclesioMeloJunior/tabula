use crate::config::genesis::Genesis;
use crate::crypto::hasher::Blake256Hasher;
use crate::trie::{key::Key, Trie};
use hex;

pub struct State {
    pub trie: Trie<Blake256Hasher>,
}

impl State {
    pub fn from_genesis(genesis: Genesis) -> Self {
        let mut t = Trie::<Blake256Hasher>::new();
        for (k, v) in &genesis.raw.top {
            let key = hex::decode(k.strip_prefix("0x").unwrap()).unwrap();
            let key = Key::new(&key);

            let value = hex::decode(v.strip_prefix("0x").unwrap()).unwrap();
            let value = Some(value);

            t.insert(key, value).unwrap();
        }
        State { trie: t }
    }
}
