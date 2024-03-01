#[derive(Debug, PartialEq)]
pub enum StorageError {}

pub trait Storage {
    type Key;
    type Value;
    type Error;

    type StorageResult<T> = std::result::Result<T, Self::Error>;

    fn get(&self, key: &Self::Key) -> Self::StorageResult<Option<&Self::Value>>;
    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Self::StorageResult<()>;

    // removes the value and returns if it exists
    fn remove(&mut self, key: &Self::Key) -> Self::StorageResult<Option<Self::Value>>;
}
