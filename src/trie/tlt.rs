use super::{
    key::Key,
    recorder::{InMemoryRecorder, Recorder},
    traits::Storage,
    Trie, TrieError, TrieStorageValueThreshold,
};
use crate::crypto::hasher::Hasher;

use super::changeset::Changeset;

pub struct NestedTransaction {
    current: Option<Changeset>,
    transactions: Vec<Changeset>,
}

#[derive(Debug, PartialEq)]
pub enum NestedTransactionError {
    NoTransactionsToCommit,
    NoTransactionsToRollback,
}

impl NestedTransaction {
    pub fn new() -> Self {
        NestedTransaction {
            current: None,
            transactions: vec![],
        }
    }

    fn commit_transaction(&mut self) -> Result<(), NestedTransactionError> {
        match (self.current.take(), self.transactions.pop()) {
            (Some(current_change_set), Some(previous_transaction)) => {
                current_change_set.merge_over(&previous_transaction);
                self.current = Some(current_change_set);
                Ok(())
            }
            (Some(_), None) => Ok(()),
            _ => Err(NestedTransactionError::NoTransactionsToCommit),
        }
    }

    fn rollback_transaction(&mut self) -> Result<(), NestedTransactionError> {
        if self.current.is_none() && self.transactions.len() == 0 {
            return Err(NestedTransactionError::NoTransactionsToRollback);
        }
        self.current = self.transactions.pop();
        Ok(())
    }

    fn start_transaction(&mut self) {
        if let Some(t) = self.current.take() {
            self.transactions.push(t);
        }
        self.current = Some(Changeset::new());
    }
}

#[derive(Debug, PartialEq)]
pub enum CommitError {
    TransactionsVectorNotEmpty,
}

// TLT - Transactional Lazy Trie
pub struct TLT<'a, H>
where
    H: Hasher,
{
    pub nested_transactions: NestedTransaction,
    pub trie: &'a mut Trie<H>,
    pub recorder: InMemoryRecorder<Vec<u8>, Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub enum TLTError {
    FailToGetFromNestedTransaction,
    FailToGetFromTrie(TrieError),
}

pub type TLTResult<T> = std::result::Result<T, TLTError>;

impl<'a, H> TLT<'a, H>
where
    H: Hasher,
{
    pub fn new(trie: &'a mut Trie<H>) -> Self {
        TLT {
            trie,
            nested_transactions: NestedTransaction::new(),
            recorder: InMemoryRecorder::new(),
        }
    }

    fn commit(&self, v: TrieStorageValueThreshold) -> Result<(), CommitError> {
        if self.nested_transactions.transactions.len() > 0 {
            return Err(CommitError::TransactionsVectorNotEmpty);
        }

        Ok(())
    }

    fn get(&mut self, key: Vec<u8>) -> TLTResult<Option<Vec<u8>>> {
        {
            if let Some(ref mut current) = self.nested_transactions.current {
                match current.get(&key, &self.recorder) {
                    Err(_) => return Err(TLTError::FailToGetFromNestedTransaction),
                    Ok(r) => match r {
                        Some(value) => return Ok(Some(value.clone())),
                        _ => {}
                    },
                }
            }
        }

        {
            let nibble_encoded_key = Key::new(&key);
            match self.trie.get(&nibble_encoded_key, &self.recorder) {
                Err(err) => return Err(TLTError::FailToGetFromTrie(err)),
                Ok(r) => match r {
                    Some(value) => return Ok(Some(value.clone())),
                    _ => {
                        println!("here!")
                    }
                },
            }
        }

        Ok(Some(vec![]))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        crypto::hasher::Blake256Hasher,
        trie::{
            codec::decode_node, key::Key, recorder::InMemoryRecorder, traits::Storage, Trie, V1,
        },
    };
    use hex_literal::hex;

    use super::TLT;

    #[test]
    fn test_get_value_that_is_on_ref_node() {
        let mut in_mem_recorder = InMemoryRecorder::new();
        let mut decoded_trie: Trie<Blake256Hasher>;

        let mut tlt = {
            let mut trie = Trie::<Blake256Hasher>::new();
            trie.insert(Key::new(&hex!("aabb")), Some(vec![0; 40]))
                .unwrap();

            trie.insert(Key::new(&hex!("aa22")), Some(vec![0; 39]))
                .unwrap();

            trie.insert(Key::new(&hex!("a128")), Some(vec![0; 38]))
                .unwrap();

            let mut encoded_iter = trie.encode_trie_root(V1, &mut in_mem_recorder).unwrap();
            let decoded_root =
                decode_node::<Blake256Hasher>(&mut encoded_iter, &mut in_mem_recorder).unwrap();

            decoded_trie = Trie::<Blake256Hasher> { root: decoded_root };
            TLT::new(&mut decoded_trie)
        };

        tlt.recorder = in_mem_recorder;

        // trying to get the value for the key &hex!("aabb")
        let expected_value = Some(vec![0; 40]);
        let result = tlt.get(hex!("aabb").to_vec()).unwrap();
        assert_eq!(expected_value, result)
    }
}
