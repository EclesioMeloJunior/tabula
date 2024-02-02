mod key;

use crate::crypto::hasher::{Blake256Hasher, Hasher};
use key::Key;

type StorageValue = Option<Vec<u8>>;

#[derive(Debug, PartialEq, Clone)]
enum VersionedStorageValue<H: Hasher> {
    RawStorageValue(StorageValue),
    HashedStorageValue(H::Out),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Leaf<H: Hasher> {
    partial_key: Key,
    storage_value: VersionedStorageValue<H>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Branch<H: Hasher> {
    partial_key: Key,
    storage_value: VersionedStorageValue<H>,
    children: [Element<H>; 16],
}

#[derive(Debug, PartialEq, Clone)]
pub enum Element<H: Hasher> {
    Leaf(Leaf<H>),
    Branch(Box<Branch<H>>),
}

impl<H: Hasher> Element<H> {
    fn already_exists(&self, key: &Key, storage_value: &StorageValue) -> bool {
        let (element_key, element_storage_value) = match self {
            Element::Branch(branch) => (&branch.partial_key, &branch.storage_value),
            Element::Leaf(leaf) => (&leaf.partial_key, &leaf.storage_value),
        };

        let storage_value_eq = match element_storage_value {
            VersionedStorageValue::RawStorageValue(raw) => raw.eq(storage_value),
            VersionedStorageValue::HashedStorageValue(hashed) => {
                let hashed_value = H::hash(storage_value.clone().map_or(vec![], |v| v).as_ref());
                hashed.eq(&hashed_value)
            }
        };

        element_key.eq(key) && storage_value_eq
    }
}

type Node<H> = Option<Element<H>>;

#[derive(Default, Debug, PartialEq)]
pub struct Trie<H: Hasher> {
    root: Node<H>,
}

#[derive(Debug, PartialEq)]
pub enum TrieError {
    InsertionFailed,
}

impl<H: Hasher> Trie<H> {
    fn insert(&mut self, key: Key, value: StorageValue) -> Result<(), TrieError> {
        let root: Node<H> = match self.root.take() {
            Some(ref mut node) => self.insert_recursively(node, key, value)?, //self.insert_on_element(element, key, value),
            None => Some(Element::Leaf(Leaf {
                partial_key: key,
                storage_value: VersionedStorageValue::RawStorageValue(value),
            })),
        };

        self.root = root;
        Ok(())
    }

    fn insert_recursively(
        &mut self,
        element: &mut Element<H>,
        key: Key,
        value: StorageValue,
    ) -> Result<Node<H>, TrieError> {
        if element.already_exists(&key, &value) {
            return Ok(Some(element.clone()));
        }

        match element {
            Element::Leaf(leaf) => unimplemented!(), // self.insert_on_leaf(),
            Element::Branch(branch) => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::hasher::Blake256Hasher;

    use super::{key::Key, Element, Leaf, Trie, VersionedStorageValue};
    use hex_literal::hex;

    #[test]
    fn trie_empty_insert_key_value() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Leaf(Leaf {
                partial_key: Key::new(&hex!("aabbcc")),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![0, 1, 2, 3, 4])),
            })),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn inserting_same_key_twice() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Leaf(Leaf {
                partial_key: Key::new(&hex!("aabbcc")),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![0, 1, 2, 3, 4])),
            })),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn inserting_more_keys() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("aabbcc0d")), Some(vec![0, 0, 0, 0, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Leaf(Leaf {
                partial_key: Key::new(&hex!("aabbcc")),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![0, 1, 2, 3, 4])),
            })),
        };

        assert_eq!(expected, t);
    }
}
