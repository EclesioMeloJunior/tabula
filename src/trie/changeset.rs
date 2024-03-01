use std::collections::{HashMap, HashSet};

use super::traits::Storage;

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
    upserts: HashMap<Vec<u8>, Vec<u8>>,
    deletes: HashSet<Vec<u8>>,
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
    type Error = ();

    fn get(&self, key: &Self::Key) -> Self::StorageResult<Option<&Self::Value>> {
        unimplemented!()
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Self::StorageResult<()> {
        unimplemented!()
    }

    fn remove(&mut self, key: &Self::Key) -> Self::StorageResult<Option<Self::Value>> {
        unimplemented!()
    }
}
