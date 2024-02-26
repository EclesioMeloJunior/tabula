use crate::crypto::hasher::Hasher;
use std::error::Error;

use super::Trie;

pub trait Storage {
    type Key;
    type Value;

    fn get(key: &Self::Key) -> Result<Option<&Self::Value>, Box<dyn Error>>;
    fn set(key: Self::Key, value: Self::Value) -> Result<(), Box<dyn Error>>;

    // removes the value and returns if it exists
    fn remove(key: &Self::Key) -> Result<Option<Self::Value>, Box<dyn Error>>;
}

pub trait Transactions {
    fn start_transaction();
    fn rollback_transaction();
    fn commit_transaction();
}

// TLT - Transactional Lazy Trie
pub struct TLT<S, T, H>
where
    S: Storage,
    T: Transactions,
    H: Hasher,
{
    pub storage: S,
    pub nested_transactions: T,

    pub trie: Trie<H>,
}
