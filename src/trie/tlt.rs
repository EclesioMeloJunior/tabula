use super::{Trie, TrieStorageValueThreshold};
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
}

#[derive(Debug, PartialEq)]
pub enum TLTError {}

pub type TLTResult<T> = std::result::Result<T, TLTError>;

impl<'a, H> TLT<'a, H>
where
    H: Hasher,
{
    pub fn new(trie: &'a mut Trie<H>) -> Self {
        TLT {
            trie,
            nested_transactions: NestedTransaction::new(),
        }
    }

    fn commit(&self, v: TrieStorageValueThreshold) -> Result<(), CommitError> {
        if self.nested_transactions.transactions.len() > 0 {
            return Err(CommitError::TransactionsVectorNotEmpty);
        }

        Ok(())
    }

    fn get(&self, key: Vec<u8>) -> TLTResult<Option<Vec<u8>>> {
        Ok(Some(vec![]))
    }
}

#[cfg(test)]
mod test {
    use super::NestedTransaction;

    fn test_nested_transaction() {
        let mut nt = NestedTransaction::new();
        nt.start_transaction();
    }
}
