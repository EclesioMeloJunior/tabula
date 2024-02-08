mod key;

use std::{ascii::AsciiExt, default};

use crate::crypto::hasher::Hasher;
use key::Key;

fn split_child_index_from_key(
    partial_key: &Key,
    common_prefix_len: usize,
) -> Result<(u8, Key), TrieError> {
    let (child_index, rest) = match partial_key.child_index(common_prefix_len) {
        (Some(child_index), Some(rest_partial_key)) => (child_index.to_owned(), rest_partial_key),
        (Some(child_index), None) => (child_index.to_owned(), Key::from(vec![])),
        _ => return Err(TrieError::CannotGetChildIndex),
    };

    return Ok((child_index, rest));
}

type StorageValue = Option<Vec<u8>>;

#[derive(Debug, PartialEq, Clone)]
enum VersionedStorageValue<H: Hasher> {
    RawStorageValue(StorageValue),
    HashedStorageValue(H::Out),
}

impl<H: Hasher> Default for VersionedStorageValue<H> {
    fn default() -> Self {
        Self::RawStorageValue(None)
    }
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct Leaf<H: Hasher> {
    partial_key: Key,
    storage_value: VersionedStorageValue<H>,
}

impl<H: Hasher> Leaf<H> {
    fn new(key: Key, storage_value: VersionedStorageValue<H>) -> Self {
        Leaf {
            partial_key: key,
            storage_value,
        }
    }

    fn to_element(&self) -> Element<H> {
        Element::Leaf(self.to_owned())
    }

    // changes the current leaf to be a child of some other branch
    // it updates its own partial_key to be the rest after the child
    // index and return the child index
    fn as_child(&mut self, common_prefix_len: usize) -> Result<usize, TrieError> {
        let (child_index, rest) = split_child_index_from_key(&self.partial_key, common_prefix_len)?;
        self.partial_key = rest;
        Ok(child_index as usize)
    }

    fn as_branch(&self) -> Branch<H> {
        Branch {
            partial_key: self.partial_key.clone(),
            storage_value: self.storage_value.clone(),
            children: Default::default(),
        }
    }

    fn encoded_header(&self) -> Vec<u8> {
        let (variant, remaining): (u8, u8) = match self.storage_value {
            VersionedStorageValue::RawStorageValue(_) => (0b01000000, 0b00111111),
            VersionedStorageValue::HashedStorageValue(_) => (0b00100000, 0b00011111),
        };

        self.partial_key.encode_len(variant, remaining)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Branch<H: Hasher> {
    partial_key: Key,
    storage_value: VersionedStorageValue<H>,
    children: [Node<H>; 16],
}

impl<H: Hasher> Branch<H> {
    fn new_empty() -> Self {
        Branch {
            partial_key: Key::from(vec![]),
            storage_value: VersionedStorageValue::RawStorageValue(None),
            children: Default::default(),
        }
    }

    fn new(key: Key, value: VersionedStorageValue<H>) -> Self {
        Branch {
            partial_key: key,
            storage_value: value,
            children: Default::default(),
        }
    }

    fn as_child(&mut self, common_prefix_len: usize) -> Result<usize, TrieError> {
        let (child_index, rest) = split_child_index_from_key(&self.partial_key, common_prefix_len)?;
        self.partial_key = rest;
        Ok(child_index as usize)
    }

    fn to_element(&self) -> Element<H> {
        Element::Branch(Box::new(self.to_owned()))
    }

    fn children_bitmap(&self) -> [u8; 2] {
        let mut bitmap: u16 = 0;
        let one: u16 = 1;

        for (idx, child) in (&self.children).into_iter().enumerate() {
            if child.is_some() {
                bitmap |= one << idx;
            }
        }
        bitmap.to_le_bytes()
    }

    fn encoded_header(&self) -> Vec<u8> {
        let (variant, remaining): (u8, u8) = match self.storage_value {
            VersionedStorageValue::RawStorageValue(None) => (0b10000000, 0b00111111),
            VersionedStorageValue::RawStorageValue(_) => (0b11000000, 0b00111111),
            VersionedStorageValue::HashedStorageValue(_) => (0b00010000, 0b00001111),
        };

        self.partial_key.encode_len(variant, remaining)
    }
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

    fn encoded_header(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::with_capacity(1);
        let (node_variant, partial_key_length): (u8, usize) = match self {
            Element::Leaf(leaf) => match leaf.storage_value {
                VersionedStorageValue::RawStorageValue(_) => (0b01000000, leaf.partial_key.0.len()),
                VersionedStorageValue::HashedStorageValue(_) => {
                    (0b00100000, leaf.partial_key.0.len())
                }
            },
            Element::Branch(branch) => match branch.storage_value {
                VersionedStorageValue::RawStorageValue(_) => {
                    (0b10000000, branch.partial_key.0.len())
                }
                VersionedStorageValue::HashedStorageValue(_) => {
                    (0b00010000, branch.partial_key.0.len())
                }
            },
        };

        encoded
    }
}

trait Encodable {
    fn encode_header(&self) -> Vec<u8>;
}

type Node<H> = Option<Element<H>>;

#[derive(Default, Debug, PartialEq)]
pub struct Trie<H: Hasher> {
    root: Node<H>,
}

#[derive(Debug, PartialEq)]
pub enum TrieError {
    InsertionFailed,
    CannotGetChildIndex,
    StorageValueNotFound,
}

impl<H: Hasher> Trie<H> {
    fn encode(&self, version: u8) -> Vec<u8> {
        match &self.root {
            Some(element) => self.encode_trie_root(&element, version),
            None => vec![0b00000000],
        }
    }

    fn encode_trie_root(&self, element: &Element<H>, version: u8) -> Vec<u8> {
        match element {
            Element::Leaf(leaf) => {
                let header = leaf.encoded_header();
                let partial_key: Vec<u8> = leaf.partial_key.into();
                let storage_value = match leaf.storage_value {
                    VersionedStorageValue::RawStorageValue(Some(v)) => {
                        unimplemented!("need to scale encode the object")
                    },
                    VersionedStorageValue::RawStorageValue(None) => vec![],
                    VersionedStorageValue::HashedStorageValue(hash) => hash.to_vec(),
                }
            }
        }
        vec![]
    }

    fn get(&self, key: &Key) -> Result<StorageValue, TrieError> {
        match self.root.clone() {
            Some(element) => self.get_recursively(element, key),
            None => Ok(None),
        }
    }

    fn get_recursively(&self, element: Element<H>, key: &Key) -> Result<StorageValue, TrieError> {
        match element {
            Element::Leaf(leaf) => {
                if !leaf.partial_key.eq(key) {
                    return Err(TrieError::StorageValueNotFound);
                }

                match leaf.storage_value {
                    VersionedStorageValue::RawStorageValue(value) => Ok(value.clone()),
                    VersionedStorageValue::HashedStorageValue(_) => unimplemented!(),
                }
            }
            Element::Branch(branch) => {
                if !branch.partial_key.eq(key) {
                    let common_prefix_key = branch.partial_key.common_length(&key);
                    let (child_index, key_rest) =
                        split_child_index_from_key(&key, common_prefix_key)?;

                    let child = branch.children[child_index as usize].clone();
                    return match child {
                        Some(element) => self.get_recursively(element, &key_rest),
                        _ => Err(TrieError::StorageValueNotFound),
                    };
                }

                match branch.storage_value {
                    VersionedStorageValue::RawStorageValue(value) => Ok(value.clone()),
                    VersionedStorageValue::HashedStorageValue(_) => unimplemented!(),
                }
            }
        }
    }

    fn insert(&mut self, key: Key, value: StorageValue) -> Result<(), TrieError> {
        let root: Node<H> = match self.root.take() {
            Some(ref mut node) => self.insert_recursively(node, key, value)?,
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
            Element::Leaf(leaf) => self.insert_on_leaf(leaf, key, value),
            Element::Branch(branch) => self.insert_on_branch(branch, key, value),
        }
    }

    fn insert_on_leaf(
        &mut self,
        leaf_element: &mut Leaf<H>,
        key: Key,
        value: StorageValue,
    ) -> Result<Node<H>, TrieError> {
        if leaf_element.partial_key.eq(&key) || key.0.len() == 0 {
            leaf_element.storage_value = VersionedStorageValue::RawStorageValue(value);
            return Ok(Some(leaf_element.to_element()));
        }

        // 1. none of the keys shares a prefix key, then a new branch
        // will be created with an empty partial key, then the current leaf
        // element will be a children and the inserted key and value another children
        // 2. keys shares some prefix key
        //   2.a the shared prefix is equal to the current leaf node, then we should transform
        //       the leaf node into a branch, conserving its storage value and the key and value
        //       be a children of the new branch node
        //   2.b the shared prefix is equal to the key beign inserted, then a new branch will be
        //       created and it will have the key and value and the current leaf node will be a children
        //       of the new branch node
        //   2.c in this case the shared prefix is not equal the complete key nor the complete leaf partial_key
        //       which means that a branch node will be created but it will not hold any value, and the current
        //       leaf node will become a child also the remaining key and the value will become another child
        let common_prefix_len = leaf_element.partial_key.common_length(&key);

        if common_prefix_len == 0 {
            let mut branch_element = Branch::<H>::new_empty();
            let child_index = leaf_element.as_child(common_prefix_len)?;
            branch_element.children[child_index] = Some(leaf_element.to_element());

            let mut new_leaf = Leaf::new(key, VersionedStorageValue::RawStorageValue(value));
            let child_index = new_leaf.as_child(common_prefix_len)?;

            branch_element.children[child_index] = Some(new_leaf.to_element());
            return Ok(Some(branch_element.to_element()));
        }

        if common_prefix_len == leaf_element.partial_key.0.len() {
            let mut new_leaf = Leaf::new(key, VersionedStorageValue::RawStorageValue(value));
            let child_index = new_leaf.as_child(common_prefix_len)?;

            let mut branch = leaf_element.as_branch();
            branch.children[child_index] = Some(new_leaf.to_element());
            return Ok(Some(branch.to_element()));
        }

        if common_prefix_len == key.0.len() {
            let child_index = leaf_element.as_child(common_prefix_len)?;
            let mut branch = Branch::<H>::new(key, VersionedStorageValue::RawStorageValue(value));
            branch.children[child_index] = Some(leaf_element.to_element());
            return Ok(Some(branch.to_element()));
        }

        let mut branch = Branch::<H>::new_empty();
        branch.partial_key = key.new_partial_key(common_prefix_len);

        let mut new_leaf = Leaf::<H>::new(key, VersionedStorageValue::RawStorageValue(value));
        let child_index = new_leaf.as_child(common_prefix_len)?;

        branch.children[child_index] = Some(new_leaf.to_element());

        let child_index = leaf_element.as_child(common_prefix_len)?;
        branch.children[child_index] = Some(leaf_element.to_element());
        Ok(Some(branch.to_element()))
    }

    fn insert_on_branch(
        &mut self,
        branch_element: &mut Branch<H>,
        key: Key,
        value: StorageValue,
    ) -> Result<Node<H>, TrieError> {
        if branch_element.partial_key.eq(&key) || key.0.len() == 0 {
            branch_element.storage_value = VersionedStorageValue::RawStorageValue(value);
            return Ok(Some(branch_element.to_element()));
        }

        // 1. none of the keys shares a prefix, a new branch will be created
        // with empty partial key, the current branch will become a child
        // of the new created branch and we will keep inserting the value in its
        // respective children slot
        // 2. keys shares some prefix key
        //   2.a the shared prefix is equal to the current branch node, then the current
        //       branch node keeps as it is, we find the child index of the inserted key
        //       if the child index is None then it becomes a leaf, if it is not empty
        //       then we call insert recursively passing the child node, key and value
        //   2.b The shared key is equal to key being insert, then a branch node will be
        //       created with the key and value in it, the current branch will be updated
        //       to br child of the new created branch
        //   2.c both shares a part of the key, then a new branch will be created containing
        //       the shared prefix, the remaining key of the current branch will be a new node
        //       as a child of the created branch, same for the key and value being inserted
        //       that will be another child in the created branch
        let common_prefix_len = branch_element.partial_key.common_length(&key);

        if common_prefix_len == 0 {
            let mut branch_empty = Branch::<H>::new_empty();
            let child_index = branch_element.as_child(common_prefix_len)?;
            branch_empty.children[child_index] = Some(branch_element.to_element());

            let mut new_leaf = Leaf::new(key, VersionedStorageValue::RawStorageValue(value));
            let child_index = new_leaf.as_child(common_prefix_len)?;

            branch_empty.children[child_index] = Some(new_leaf.to_element());
            return Ok(Some(branch_empty.to_element()));
        }

        if common_prefix_len == branch_element.partial_key.0.len() {
            let (child_index, key_rest) = split_child_index_from_key(&key, common_prefix_len)?;
            branch_element.children[child_index as usize] =
                match branch_element.children[child_index as usize].clone() {
                    Some(ref mut element) => self.insert_recursively(element, key_rest, value)?,
                    None => Some(
                        Leaf::new(key_rest, VersionedStorageValue::RawStorageValue(value))
                            .to_element(),
                    ),
                };

            return Ok(Some(branch_element.to_element()));
        }

        if common_prefix_len == key.0.len() {
            let mut branch = Branch::<H>::new(key, VersionedStorageValue::RawStorageValue(value));
            let child_index = branch_element.as_child(common_prefix_len)?;
            branch.children[child_index] = Some(branch_element.to_element());
            return Ok(Some(branch.to_element()));
        }

        let mut new_branch = Branch::<H>::new(
            key.new_partial_key(common_prefix_len),
            VersionedStorageValue::RawStorageValue(None),
        );

        let (child_index, key_rest) = split_child_index_from_key(&key, common_prefix_len)?;
        new_branch.children[child_index as usize] = Some(
            Leaf::<H>::new(key_rest, VersionedStorageValue::RawStorageValue(value)).to_element(),
        );

        let child_index = branch_element.as_child(common_prefix_len)?;
        new_branch.children[child_index as usize] = Some(branch_element.to_element());
        Ok(Some(new_branch.to_element()))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::hasher::Blake256Hasher;

    use super::*;
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

        // using empty vec is the same as updating the same key
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::from(vec![]), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Leaf(Leaf {
                partial_key: Key::new(&hex!("aabbcc")),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![0, 1, 2, 3, 4])),
            })),
        };

        assert_eq!(expected, t);

        // updating, now passing the same key
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![1, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Leaf(Leaf {
                partial_key: Key::new(&hex!("aabbcc")),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![1, 1])),
            })),
        };

        assert_eq!(expected, t);

        // updating, now using empty vec and another value
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::from(vec![]), Some(vec![1, 1])).unwrap();

        let expected = Trie {
            root: Some(Element::Leaf(Leaf {
                partial_key: Key::new(&hex!("aabbcc")),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![1, 1])),
            })),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn inserting_another_key_without_common_prefix_on_existing_leaf() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("11bbcc0d")), Some(vec![5, 0, 0, 0, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key::from(vec![]),
                children: [
                    None,
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![1, 11, 11, 12, 12, 0, 13]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            5, 0, 0, 0, 1,
                        ])),
                    })),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![10, 11, 11, 12, 12]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            0, 1, 2, 3, 4,
                        ])),
                    })),
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
                storage_value: VersionedStorageValue::RawStorageValue(None),
            }))),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn leaf_should_become_branch() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabb")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("aabbcc")), Some(vec![5, 0, 0, 0, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key(vec![10, 10, 11, 11]),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![0, 1, 2, 3, 4])),
                children: [
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![12]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            5, 0, 0, 0, 1,
                        ])),
                    })),
                    None,
                    None,
                    None,
                ],
            }))),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn inserted_key_value_should_be_branch_and_leaf_should_child() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aabb")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("aa")), Some(vec![5, 0, 0, 0, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key(vec![10, 10]),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![5, 0, 0, 0, 1])),
                children: [
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![11]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            0, 1, 2, 3, 4,
                        ])),
                    })),
                    None,
                    None,
                    None,
                    None,
                ],
            }))),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn inserted_and_leaf_should_be_child_of_common_branch() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aa11")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("aa22")), Some(vec![5, 0, 0, 0, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key(vec![10, 10]),
                storage_value: VersionedStorageValue::RawStorageValue(None),
                children: [
                    None,
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![1]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            0, 1, 2, 3, 4,
                        ])),
                    })),
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![2]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            5, 0, 0, 0, 1,
                        ])),
                    })),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
            }))),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn inserting_on_branches_without_common_prefix() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aa11")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("aa22")), Some(vec![5, 0, 0, 0, 1]))
            .unwrap();
        t.insert(Key::new(&hex!("1133")), Some(vec![1, 1, 1, 1, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key::from(vec![]),
                storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
                children: [
                    None,
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![1, 3, 3]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            1, 1, 1, 1, 1,
                        ])),
                    })),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(Element::Branch(Box::new(Branch {
                        partial_key: Key(vec![10]),
                        storage_value: VersionedStorageValue::RawStorageValue(None),
                        children: [
                            None,
                            Some(Element::Leaf(Leaf {
                                partial_key: Key(vec![1]),
                                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                                    0, 1, 2, 3, 4,
                                ])),
                            })),
                            Some(Element::Leaf(Leaf {
                                partial_key: Key(vec![2]),
                                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                                    5, 0, 0, 0, 1,
                                ])),
                            })),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        ],
                    }))),
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
            }))),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn inserting_on_branches_with_common_prefix() {
        let mut t: Trie<Blake256Hasher> = Trie::default();
        t.insert(Key::new(&hex!("aa11")), Some(vec![0, 1, 2, 3, 4]))
            .unwrap();
        t.insert(Key::new(&hex!("aa22")), Some(vec![5, 0, 0, 0, 1]))
            .unwrap();
        t.insert(Key::new(&hex!("aa33")), Some(vec![1, 0, 0, 0, 1]))
            .unwrap();
        t.insert(Key::new(&hex!("aa2211")), Some(vec![4, 4, 0, 0, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key(vec![10, 10]),
                storage_value: VersionedStorageValue::RawStorageValue(None),
                children: [
                    None,
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![1]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            0, 1, 2, 3, 4,
                        ])),
                    })),
                    Some(Element::Branch(Box::new(Branch {
                        partial_key: Key(vec![2]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            5, 0, 0, 0, 1,
                        ])),
                        children: [
                            None,
                            Some(Element::Leaf(Leaf {
                                partial_key: Key(vec![1]),
                                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                                    4, 4, 0, 0, 1,
                                ])),
                            })),
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                        ],
                    }))),
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![3]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            1, 0, 0, 0, 1,
                        ])),
                    })),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
            }))),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn common_prefix_equal_key_beign_inserted_on_branch_node() {
        let mut t: Trie<Blake256Hasher> = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key::new(&[0x01, 0x02, 0xff]),
                storage_value: VersionedStorageValue::RawStorageValue(None),
                children: Default::default(),
            }))),
        };

        t.insert(Key::new(&[0x01]), Some(vec![1, 1])).unwrap();

        let expected = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key::new(&[0x01]),
                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![1, 1])),
                children: [
                    Some(Element::Branch(Box::new(Branch {
                        partial_key: Key(vec![2, 15, 15]),
                        storage_value: VersionedStorageValue::RawStorageValue(None),
                        children: Default::default(),
                    }))),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
            }))),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn both_branch_and_key_shares_a_prefix() {
        let mut t: Trie<Blake256Hasher> = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key::new(&[0x01, 0x02, 0xff]),
                storage_value: VersionedStorageValue::RawStorageValue(None),
                children: Default::default(),
            }))),
        };

        t.insert(Key::new(&[0x01, 0x03, 0xff]), Some(vec![1, 1]))
            .unwrap();

        let expected = Trie {
            root: Some(Element::Branch(Box::new(Branch {
                partial_key: Key(vec![0, 1, 0]),
                storage_value: VersionedStorageValue::RawStorageValue(None),
                children: [
                    None,
                    None,
                    Some(Element::Branch(Box::new(Branch {
                        partial_key: Key(vec![15, 15]),
                        storage_value: VersionedStorageValue::RawStorageValue(None),
                        children: Default::default(),
                    }))),
                    Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![15, 15]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![1, 1])),
                    })),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
            }))),
        };

        assert_eq!(expected, t);
    }

    #[test]
    fn getting_values_from_trie() {
        let mut t: Trie<Blake256Hasher> = Default::default();

        let keys: Vec<(Key, StorageValue)> = vec![
            (Key::new(&[0x01, 0x03, 0xff]), Some(vec![1, 1])),
            (Key::new(&[0x01]), Some(vec![0, 2, 0, 1])),
            (Key::new(&[0x03]), Some(vec![0, 2, 0, 2])),
            (Key::new(&[0x04]), Some(vec![0, 2, 0, 3])),
            (Key::new(&hex!("0a9090ff")), Some(vec![0xff, 0xff, 0x01])),
        ];

        for (k, v) in &keys {
            t.insert(k.clone(), v.clone()).unwrap();
        }

        for (k, expected) in keys {
            let sv = t.get(&k).unwrap();
            assert_eq!(expected, sv);
        }

        let not_found = t.get(&Key(vec![0, 0, 0, 0, 1]));
        assert_eq!(not_found, Err(TrieError::StorageValueNotFound));
    }

    #[test]
    fn branch_children_bitmap() {
        let branch = Branch::<Blake256Hasher> {
            partial_key: Key(vec![0, 1, 0]),
            storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
            children: [
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
            ],
        };

        let expected_bitmap: [u8; 2] = [0xff, 0xff];
        assert_eq!(branch.children_bitmap(), expected_bitmap);

        let branch = Branch::<Blake256Hasher> {
            partial_key: Key(vec![0, 1, 0]),
            storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
            children: [
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
            ],
        };

        let expected_bitmap: [u8; 2] = [0x00, 0xff];
        assert_eq!(branch.children_bitmap(), expected_bitmap);

        let branch = Branch::<Blake256Hasher> {
            partial_key: Key(vec![0, 1, 0]),
            storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
            children: [
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                Some(Element::Leaf(Default::default())),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
        };

        let expected_bitmap: [u8; 2] = [0xff, 0x00];
        assert_eq!(branch.children_bitmap(), expected_bitmap);

        let branch = Branch::<Blake256Hasher> {
            partial_key: Key(vec![0, 1, 0]),
            storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
            children: [
                Some(Element::Leaf(Default::default())),
                None,
                None,
                None,
                None,
                None,
                Some(Element::Leaf(Default::default())),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(Element::Leaf(Default::default())),
            ],
        };

        let expected_bitmap: [u8; 2] = [0b01000001, 0b10000000];
        assert_eq!(branch.children_bitmap(), expected_bitmap);
    }

    #[test]
    fn test_element_header_encoding() {
        let leafs = vec![
            (
                Leaf::<Blake256Hasher> {
                    partial_key: Key(vec![1, 2, 3]),
                    storage_value: Default::default(),
                },
                vec![0b01000011],
            ),
            (
                Leaf::<Blake256Hasher> {
                    partial_key: Key([0; 63].to_vec()),
                    storage_value: Default::default(),
                },
                vec![0b01111111],
            ),
            (
                Leaf::<Blake256Hasher> {
                    partial_key: Key([0; 64].to_vec()),
                    storage_value: Default::default(),
                },
                vec![0b01111111, 0b00000001],
            ),
            (
                Leaf::<Blake256Hasher> {
                    partial_key: Key([0; 319].to_vec()),
                    storage_value: Default::default(),
                },
                vec![0b01111111, 0b11111111, 0b0000001],
            ),
            (
                Leaf::<Blake256Hasher> {
                    partial_key: Key(vec![1, 2, 3]),
                    storage_value: VersionedStorageValue::HashedStorageValue([0; 32]),
                },
                vec![0b00100011],
            ),
            (
                Leaf::<Blake256Hasher> {
                    partial_key: Key([0; 31].to_vec()),
                    storage_value: VersionedStorageValue::HashedStorageValue([0; 32]),
                },
                vec![0b00111111],
            ),
            (
                Leaf::<Blake256Hasher> {
                    partial_key: Key([0; 32].to_vec()),
                    storage_value: VersionedStorageValue::HashedStorageValue([0; 32]),
                },
                vec![0b00111111, 0b00000001],
            ),
        ];

        for (leaf, expected_enc_header) in leafs {
            let out = leaf.encoded_header();
            assert_eq!(out, expected_enc_header);
        }

        let branches = vec![
            (
                Branch::<Blake256Hasher> {
                    partial_key: Key(vec![0, 1, 2]),
                    children: Default::default(),
                    storage_value: VersionedStorageValue::RawStorageValue(None),
                },
                vec![0b10000011],
            ),
            (
                Branch::<Blake256Hasher> {
                    partial_key: Key([0; 63].to_vec()),
                    children: Default::default(),
                    storage_value: VersionedStorageValue::RawStorageValue(Some(vec![1, 2, 3])),
                },
                vec![0b11111111],
            ),
            (
                Branch::<Blake256Hasher> {
                    partial_key: Key([0; 319].to_vec()),
                    children: Default::default(),
                    storage_value: VersionedStorageValue::HashedStorageValue([0; 32]),
                },
                vec![0b00011111, 0b11111111, 0b00110001],
            ),
        ];

        for (branch, expected_enc_header) in branches {
            let out = branch.encoded_header();
            assert_eq!(out, expected_enc_header)
        }
    }
}
