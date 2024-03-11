use std::collections::{HashMap, HashSet};

use super::{traits::Storage, NodeRecorder};

#[derive(Debug, PartialEq)]
pub enum ChangesetError {
    ItemDeleted,
}

trait RemoveIf<T> {
    fn remove_if<F>(&mut self, predicate: F)
    where
        F: FnMut(&T) -> bool;
}

impl<K, V> RemoveIf<K> for HashMap<K, V> {
    fn remove_if<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&K) -> bool,
    {
        self.retain(|k, v| !predicate(k))
    }
}

impl<K> RemoveIf<K> for HashSet<K> {
    fn remove_if<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&K) -> bool,
    {
        self.retain(|k| !predicate(k))
    }
}

pub enum Change {
    Upsert { Key: Vec<u8>, Value: Vec<u8> },
    Deletion(Vec<u8>),
}

pub struct Changeset {
    pub upserts: HashMap<Vec<u8>, Vec<u8>>,
    pub deletes: HashSet<Vec<u8>>,
}

impl Changeset {
    pub fn new() -> Self {
        Changeset {
            upserts: HashMap::new(),
            deletes: HashSet::new(),
        }
    }

    pub fn merge_over(&self, other: &Changeset) -> Changeset {
        let mut updated_deletes = other.deletes.clone();
        updated_deletes.remove_if(|k| self.upserts.contains_key(k));
        updated_deletes.extend(self.deletes.clone());

        let mut updated_upserts = other.upserts.clone();
        updated_upserts.remove_if(|k| self.deletes.contains(k));
        updated_upserts.extend(self.upserts.clone());

        Changeset {
            deletes: updated_deletes,
            upserts: updated_upserts,
        }
    }
}

impl Storage for Changeset {
    type Key = Vec<u8>;
    type Value = Vec<u8>;
    type Error = ChangesetError;

    fn get(&self, key: &Self::Key, _: &NodeRecorder) -> Self::StorageResult<Option<Self::Value>> {
        if self.deletes.contains(key) {
            return Err(ChangesetError::ItemDeleted);
        }

        Ok(self.upserts.get(key).cloned())
    }

    fn insert(&mut self, key: Self::Key, value: Option<Self::Value>) -> Self::StorageResult<()> {
        self.deletes.remove(&key);

        if let Some(storage_value) = value {
            self.upserts.insert(key, storage_value);
        } else {
            self.upserts.insert(key, vec![]);
        }

        Ok(())
    }

    fn remove(&mut self, key: &Self::Key) -> Self::StorageResult<Option<Self::Value>> {
        let removed = self.upserts.remove(key);
        self.deletes.insert(key.clone());
        Ok(removed)
    }
}
