use std::{collections::HashMap, hash::Hash};

#[derive(Debug, PartialEq)]
pub enum RecorderError {
    NotFound,
}

pub trait Recorder {
    type Key = Vec<u8>;
    type Value = Vec<u8>;

    fn insert(&mut self, key: &Self::Key, value: Self::Value) -> Result<(), RecorderError>;
    fn get(&self, key: &Self::Key) -> Result<Option<&Self::Value>, RecorderError>;
}

pub struct InMemoryRecorder<K, V> {
    mem: HashMap<K, V>,
}

impl<K, V> InMemoryRecorder<K, V> {
    pub fn new() -> Self {
        InMemoryRecorder {
            mem: HashMap::new(),
        }
    }
}

impl<K, V> Recorder for InMemoryRecorder<K, V>
where
    K: PartialEq + Clone + Eq + Hash,
{
    type Key = K;
    type Value = V;

    fn get(&self, key: &Self::Key) -> Result<Option<&Self::Value>, RecorderError> {
        Ok(self.mem.get(key))
    }

    fn insert(&mut self, key: &Self::Key, value: Self::Value) -> Result<(), RecorderError> {
        self.mem.insert(key.clone(), value);
        Ok(())
    }
}
