pub mod changeset;
pub mod codec;
pub mod key;
pub mod recorder;
pub mod tlt;
pub mod traits;
use std::hash;
use std::vec::IntoIter;

use self::codec::{decode_node, EncodedIter};
use self::recorder::{InMemoryRecorder, Recorder, RecorderError};
use self::traits::Storage;
use crate::crypto::hasher::Hasher;
use hex::decode;
use key::Key;
use parity_scale_codec::Encode;

type NodeRecorder = dyn Recorder<Key = Vec<u8>, Value = Vec<u8>>;

fn split_child_index_from_key(
    partial_key: &Key,
    common_prefix_len: usize,
) -> Result<(u8, Key), TrieError> {
    let (child_index, rest) = match partial_key.child_index(common_prefix_len) {
        (Some(child_index), Some(rest_partial_key)) => (child_index.to_owned(), rest_partial_key),
        (Some(child_index), None) => (child_index.to_owned(), Key::from(vec![])),
        _ => return Err(TrieError::CannotGetChildIndex),
    };

    Ok((child_index, rest))
}

type TrieStorageValueThreshold = usize;
type StorageValue = Option<Vec<u8>>;

pub const V0: TrieStorageValueThreshold = usize::MAX;
pub const V1: TrieStorageValueThreshold = 32;

#[derive(Debug, PartialEq, Clone)]
enum VersionedStorageValue<H: Hasher> {
    RawStorageValue(StorageValue),
    HashedStorageValue(H::Out),
}

impl<H: Hasher> VersionedStorageValue<H> {
    fn encode(&self, version: TrieStorageValueThreshold) -> Option<Vec<u8>> {
        match &self {
            VersionedStorageValue::RawStorageValue(Some(v)) if v.len() > version => {
                Some(H::hash(&v).encode())
            }
            VersionedStorageValue::RawStorageValue(Some(v)) => Some(v.encode()),
            VersionedStorageValue::RawStorageValue(None) => None,
            VersionedStorageValue::HashedStorageValue(hash) => Some(hash.encode()),
        }
    }
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

    fn encoded_header(&self, version: TrieStorageValueThreshold) -> Vec<u8> {
        let (variant, remaining): (u8, u8) = match &self.storage_value {
            VersionedStorageValue::RawStorageValue(None) => (0b01000000, 0b00111111),
            VersionedStorageValue::RawStorageValue(Some(v)) if v.len() > version => {
                (0b00100000, 0b00011111)
            }
            VersionedStorageValue::RawStorageValue(_) => (0b01000000, 0b00111111),
            VersionedStorageValue::HashedStorageValue(_) => (0b00100000, 0b00011111),
        };

        self.partial_key.encode_len(variant, remaining)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum NodeKind<H: Hasher> {
    Raw(Node<H>),
    Ref(Vec<u8>),
}

impl<H: Hasher> Default for NodeKind<H> {
    fn default() -> Self {
        NodeKind::Raw(None)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Branch<H: Hasher> {
    partial_key: Key,
    storage_value: VersionedStorageValue<H>,
    children: [NodeKind<H>; 16],
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
            let exists = match child {
                NodeKind::Raw(v) => v.is_some(),
                _ => true,
            };

            if exists {
                bitmap |= one << idx;
            }
        }

        bitmap.to_le_bytes()
    }

    fn encoded_header(&self, version: TrieStorageValueThreshold) -> Vec<u8> {
        let (variant, remaining): (u8, u8) = match &self.storage_value {
            VersionedStorageValue::RawStorageValue(None) => (0b10000000, 0b00111111),
            VersionedStorageValue::RawStorageValue(Some(v)) if v.len() > version => {
                (0b00010000, 0b00001111)
            }
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

    fn encode(
        &self,
        version: TrieStorageValueThreshold,
        recorder: &mut NodeRecorder,
    ) -> Result<Vec<u8>, RecorderError> {
        match self {
            Element::Leaf(leaf) => {
                let header = leaf.encoded_header(version);
                let key: Vec<u8> = leaf.partial_key.clone().into();
                let encoded_storage_value = leaf.storage_value.encode(version);

                if let Some(encoded_storage_value) = encoded_storage_value {
                    if version == V1 {
                        match &leaf.storage_value {
                            VersionedStorageValue::RawStorageValue(raw) => match raw {
                                Some(storage_value) if storage_value.len() > 32 => recorder
                                    .insert(&encoded_storage_value, storage_value.clone())?,
                                _ => {}
                            },
                            _ => {}
                        }
                    }

                    return Ok(vec![header, key, encoded_storage_value].concat());
                }

                Ok(vec![header, key].concat())
            }

            Element::Branch(branch) => {
                let mut encoded: Vec<u8> = Vec::new();
                let header = branch.encoded_header(version);
                encoded.extend(header);

                let key: Vec<u8> = branch.partial_key.clone().into();
                encoded.extend(key);

                let children_bitmap = branch.children_bitmap();
                encoded.extend(children_bitmap.to_vec());

                if let Some(encoded_storage_value) = branch.storage_value.encode(version) {
                    if version == V1 {
                        match &branch.storage_value {
                            VersionedStorageValue::RawStorageValue(raw) => match raw {
                                Some(storage_value) if storage_value.len() > 32 => recorder
                                    .insert(&encoded_storage_value, storage_value.clone())?,
                                _ => {}
                            },
                            _ => {}
                        }
                    }

                    encoded.extend(encoded_storage_value);
                }

                for idx in 0..branch.children.len() {
                    match &branch.children[idx] {
                        NodeKind::Raw(None) => {}
                        NodeKind::Raw(Some(child)) => match child.encode(version, recorder) {
                            Err(err) => return Err(err),
                            Ok(encoded_child) if encoded_child.len() < 32 => {
                                encoded.extend(encoded_child.encode());
                            }
                            Ok(encoded_child) => {
                                let hashed: Vec<u8> = H::hash(&encoded_child).into();
                                match recorder.insert(&hashed, encoded_child) {
                                    Err(err) => return Err(err),
                                    Ok(_) => {}
                                }
                                encoded.extend(hashed.encode());
                            }
                        },
                        NodeKind::Ref(ref_child) => {
                            encoded.extend(ref_child.encode());
                        }
                    };
                }

                Ok(encoded)
            }
        }
    }
}

type Node<H> = Option<Element<H>>;

#[derive(Default, Debug, PartialEq)]
pub struct Trie<H: Hasher> {
    root: Node<H>,
}

#[derive(Debug, PartialEq)]
pub enum TrieError {
    NodeNotRecorded(RecorderError),
    InsertionFailed,
    CannotGetChildIndex,
    StorageValueNotFound,
    FailedToDecodeNode(codec::DecodeError),
}

impl<H: Hasher> Storage for Trie<H> {
    type Key = Key;
    type Value = Vec<u8>;
    type Error = TrieError;

    // TODO: get should have acess to the storage/recorder to retrive a storage value that is
    // hased under the trie node
    fn get(
        &mut self,
        key: &Self::Key,
        recorder: &NodeRecorder,
    ) -> Self::StorageResult<Option<Self::Value>> {
        match self.root {
            Some(ref node) => match self.get_recursively(node, key, recorder) {
                Ok(storage_value) => Ok(storage_value),
                Err(err) => return Err(err),
            },
            None => Ok(None),
        }
    }

    fn insert(&mut self, key: Self::Key, value: Option<Self::Value>) -> Self::StorageResult<()> {
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

    fn remove(&mut self, key: &Self::Key) -> Self::StorageResult<Option<Self::Value>> {
        unimplemented!()
    }
}

impl<H: Hasher> Trie<H> {
    pub fn new() -> Self {
        Trie::<H> {
            root: Default::default(),
        }
    }

    pub fn root_hash(&self, version: TrieStorageValueThreshold) -> Result<Vec<u8>, RecorderError> {
        let mut recorder = InMemoryRecorder::new();
        let hashed_root = self
            .encode_trie_root(version, &mut recorder)?
            .hash::<H>()
            .encode();

        Ok(hashed_root)
    }

    fn encode_trie_root(
        &self,
        version: TrieStorageValueThreshold,
        recorder: &mut NodeRecorder,
    ) -> Result<EncodedIter, RecorderError> {
        match &self.root {
            Some(element) => Ok(EncodedIter::new(
                element.encode(version, recorder)?.into_iter(),
            )),
            None => Ok(EncodedIter::new(vec![0b00000000].into_iter())),
        }
    }

    fn get_recursively(
        &self,
        element: &Element<H>,
        key: &Key,
        recorder: &NodeRecorder,
    ) -> Result<StorageValue, TrieError> {
        match element {
            Element::Leaf(leaf) => {
                if !leaf.partial_key.eq(key) {
                    return Err(TrieError::StorageValueNotFound);
                }

                match &leaf.storage_value {
                    VersionedStorageValue::RawStorageValue(value) => Ok(value.clone()),
                    VersionedStorageValue::HashedStorageValue(hashed_value) => {
                        match recorder.get(&hashed_value.clone().into()) {
                            Ok(value) => Ok(value.cloned()),
                            Err(err) => Err(TrieError::NodeNotRecorded(err)),
                        }
                    }
                }
            }
            Element::Branch(branch) => {
                if !branch.partial_key.eq(key) {
                    let common_prefix_key = branch.partial_key.common_length(&key);
                    let (child_index, key_rest) =
                        split_child_index_from_key(&key, common_prefix_key)?;

                    let decode_child_and_find = |encoded_node: Vec<u8>, rest: Key| {
                        let mut encoded_iter = EncodedIter::new(encoded_node.into_iter());
                        let mut node = decode_node::<H>(&mut encoded_iter, recorder);
                        match node {
                            Err(err) => Err(TrieError::FailedToDecodeNode(err)),
                            Ok(None) => Err(TrieError::StorageValueNotFound),
                            Ok(Some(ref mut element)) => {
                                self.get_recursively(element, &rest, recorder)
                            }
                        }
                    };

                    let mut child = branch.children[child_index as usize].clone();
                    return match child {
                        NodeKind::Raw(None) => Err(TrieError::StorageValueNotFound),
                        NodeKind::Raw(Some(ref mut element)) => {
                            self.get_recursively(element, &key_rest, recorder)
                        }
                        NodeKind::Ref(child_ref) => {
                            if child_ref.len() < 32 {
                                decode_child_and_find(child_ref, key_rest)
                            } else {
                                match recorder.get(&child_ref) {
                                    Ok(None) => {
                                        Err(TrieError::NodeNotRecorded(RecorderError::NotFound))
                                    }
                                    Ok(Some(encoded_node)) => {
                                        decode_child_and_find(encoded_node.clone(), key_rest)
                                    }
                                    Err(err) => Err(TrieError::NodeNotRecorded(err)),
                                }
                            }
                        }
                    };
                }

                match &branch.storage_value {
                    VersionedStorageValue::RawStorageValue(value) => Ok(value.clone()),
                    VersionedStorageValue::HashedStorageValue(_) => unimplemented!(),
                }
            }
        }
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
        if key.0.len() == 0 || leaf_element.partial_key.eq(&key) {
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
            branch_element.children[child_index] = NodeKind::Raw(Some(leaf_element.to_element()));

            let (child_index, key_rest) = split_child_index_from_key(&key, common_prefix_len)?;
            let new_leaf = Leaf::new(key_rest, VersionedStorageValue::RawStorageValue(value));

            branch_element.children[child_index as usize] =
                NodeKind::Raw(Some(new_leaf.to_element()));
            return Ok(Some(branch_element.to_element()));
        }

        if common_prefix_len == leaf_element.partial_key.0.len() {
            let mut new_leaf = Leaf::new(key, VersionedStorageValue::RawStorageValue(value));
            let child_index = new_leaf.as_child(common_prefix_len)?;

            let mut branch = leaf_element.as_branch();
            branch.children[child_index] = NodeKind::Raw(Some(new_leaf.to_element()));
            return Ok(Some(branch.to_element()));
        }

        if common_prefix_len == key.0.len() {
            let child_index = leaf_element.as_child(common_prefix_len)?;
            let mut branch = Branch::<H>::new(key, VersionedStorageValue::RawStorageValue(value));
            branch.children[child_index] = NodeKind::Raw(Some(leaf_element.to_element()));
            return Ok(Some(branch.to_element()));
        }

        let mut branch = Branch::<H>::new_empty();
        branch.partial_key = key.new_partial_key(common_prefix_len);

        let mut new_leaf = Leaf::<H>::new(key, VersionedStorageValue::RawStorageValue(value));
        let child_index = new_leaf.as_child(common_prefix_len)?;

        branch.children[child_index] = NodeKind::Raw(Some(new_leaf.to_element()));

        let child_index = leaf_element.as_child(common_prefix_len)?;
        branch.children[child_index] = NodeKind::Raw(Some(leaf_element.to_element()));
        Ok(Some(branch.to_element()))
    }

    fn insert_on_branch(
        &mut self,
        branch_element: &mut Branch<H>,
        key: Key,
        value: StorageValue,
    ) -> Result<Node<H>, TrieError> {
        if branch_element.partial_key.eq(&key) {
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

        if common_prefix_len == 0 && branch_element.partial_key.0.len() > 0 {
            let mut branch_empty = Branch::<H>::new_empty();
            let child_index = branch_element.as_child(common_prefix_len)?;
            branch_empty.children[child_index] = NodeKind::Raw(Some(branch_element.to_element()));

            let mut new_leaf = Leaf::new(key, VersionedStorageValue::RawStorageValue(value));
            let child_index = new_leaf.as_child(common_prefix_len)?;

            branch_empty.children[child_index] = NodeKind::Raw(Some(new_leaf.to_element()));
            return Ok(Some(branch_empty.to_element()));
        }

        if common_prefix_len == 0 && branch_element.partial_key.0.len() == 0 {
            let (child_index, key_rest) = split_child_index_from_key(&key, 0)?;
            branch_element.children[child_index as usize] =
                match branch_element.children[child_index as usize].clone() {
                    NodeKind::Raw(Some(ref mut element)) => {
                        NodeKind::Raw(self.insert_recursively(element, key_rest, value)?)
                    }
                    NodeKind::Raw(None) => NodeKind::Raw(Some(
                        Leaf::new(key_rest, VersionedStorageValue::RawStorageValue(value))
                            .to_element(),
                    )),
                    NodeKind::Ref(_) => {
                        unimplemented!("cannot insert on trie with node ref")
                    }
                };

            return Ok(Some(branch_element.to_element()));
        }

        if common_prefix_len == branch_element.partial_key.0.len() {
            let (child_index, key_rest) = split_child_index_from_key(&key, common_prefix_len)?;
            branch_element.children[child_index as usize] =
                match branch_element.children[child_index as usize].clone() {
                    NodeKind::Raw(Some(ref mut element)) => {
                        NodeKind::Raw(self.insert_recursively(element, key_rest, value)?)
                    }
                    NodeKind::Raw(None) => NodeKind::Raw(Some(
                        Leaf::new(key_rest, VersionedStorageValue::RawStorageValue(value))
                            .to_element(),
                    )),
                    NodeKind::Ref(_) => {
                        unimplemented!("cannot insert on trie with node ref")
                    }
                };

            return Ok(Some(branch_element.to_element()));
        }

        if common_prefix_len == key.0.len() {
            let mut branch = Branch::<H>::new(key, VersionedStorageValue::RawStorageValue(value));
            let child_index = branch_element.as_child(common_prefix_len)?;
            branch.children[child_index] = NodeKind::Raw(Some(branch_element.to_element()));
            return Ok(Some(branch.to_element()));
        }

        let mut new_branch = Branch::<H>::new(
            key.new_partial_key(common_prefix_len),
            VersionedStorageValue::RawStorageValue(None),
        );

        let (child_index, key_rest) = split_child_index_from_key(&key, common_prefix_len)?;
        new_branch.children[child_index as usize] = NodeKind::Raw(Some(
            Leaf::<H>::new(key_rest, VersionedStorageValue::RawStorageValue(value)).to_element(),
        ));

        let child_index = branch_element.as_child(common_prefix_len)?;
        new_branch.children[child_index as usize] =
            NodeKind::Raw(Some(branch_element.to_element()));
        Ok(Some(new_branch.to_element()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hasher::Blake256Hasher;
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
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![1, 11, 11, 12, 12, 0, 13]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            5, 0, 0, 0, 1,
                        ])),
                    }))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![10, 11, 11, 12, 12]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            0, 1, 2, 3, 4,
                        ])),
                    }))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
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
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![12]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            5, 0, 0, 0, 1,
                        ])),
                    }))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
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
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![11]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            0, 1, 2, 3, 4,
                        ])),
                    }))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
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
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![1]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            0, 1, 2, 3, 4,
                        ])),
                    }))),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![2]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            5, 0, 0, 0, 1,
                        ])),
                    }))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
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
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![1, 3, 3]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            1, 1, 1, 1, 1,
                        ])),
                    }))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Branch(Box::new(Branch {
                        partial_key: Key(vec![10]),
                        storage_value: VersionedStorageValue::RawStorageValue(None),
                        children: [
                            NodeKind::Raw(None),
                            NodeKind::Raw(Some(Element::Leaf(Leaf {
                                partial_key: Key(vec![1]),
                                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                                    0, 1, 2, 3, 4,
                                ])),
                            }))),
                            NodeKind::Raw(Some(Element::Leaf(Leaf {
                                partial_key: Key(vec![2]),
                                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                                    5, 0, 0, 0, 1,
                                ])),
                            }))),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                        ],
                    })))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
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
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![1]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            0, 1, 2, 3, 4,
                        ])),
                    }))),
                    NodeKind::Raw(Some(Element::Branch(Box::new(Branch {
                        partial_key: Key(vec![2]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            5, 0, 0, 0, 1,
                        ])),
                        children: [
                            NodeKind::Raw(None),
                            NodeKind::Raw(Some(Element::Leaf(Leaf {
                                partial_key: Key(vec![1]),
                                storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                                    4, 4, 0, 0, 1,
                                ])),
                            }))),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                            NodeKind::Raw(None),
                        ],
                    })))),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![3]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![
                            1, 0, 0, 0, 1,
                        ])),
                    }))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
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
                    NodeKind::Raw(Some(Element::Branch(Box::new(Branch {
                        partial_key: Key(vec![2, 15, 15]),
                        storage_value: VersionedStorageValue::RawStorageValue(None),
                        children: Default::default(),
                    })))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
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
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(Some(Element::Branch(Box::new(Branch {
                        partial_key: Key(vec![15, 15]),
                        storage_value: VersionedStorageValue::RawStorageValue(None),
                        children: Default::default(),
                    })))),
                    NodeKind::Raw(Some(Element::Leaf(Leaf {
                        partial_key: Key(vec![15, 15]),
                        storage_value: VersionedStorageValue::RawStorageValue(Some(vec![1, 1])),
                    }))),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
                    NodeKind::Raw(None),
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
            let sv = t.get(&k, &InMemoryRecorder::new()).unwrap();
            assert_eq!(expected, sv);
        }

        let not_found = t.get(&Key(vec![0, 0, 0, 0, 1]), &InMemoryRecorder::new());
        assert_eq!(not_found, Err(TrieError::StorageValueNotFound));
    }

    #[test]
    fn branch_children_bitmap() {
        let branch = Branch::<Blake256Hasher> {
            partial_key: Key(vec![0, 1, 0]),
            storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
            children: [
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
            ],
        };

        let expected_bitmap: [u8; 2] = [0xff, 0xff];
        assert_eq!(branch.children_bitmap(), expected_bitmap);

        let branch = Branch::<Blake256Hasher> {
            partial_key: Key(vec![0, 1, 0]),
            storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
            children: [
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
            ],
        };

        let expected_bitmap: [u8; 2] = [0x00, 0xff];
        assert_eq!(branch.children_bitmap(), expected_bitmap);

        let branch = Branch::<Blake256Hasher> {
            partial_key: Key(vec![0, 1, 0]),
            storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
            children: [
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
            ],
        };

        let expected_bitmap: [u8; 2] = [0xff, 0x00];
        assert_eq!(branch.children_bitmap(), expected_bitmap);

        let branch = Branch::<Blake256Hasher> {
            partial_key: Key(vec![0, 1, 0]),
            storage_value: VersionedStorageValue::<Blake256Hasher>::RawStorageValue(None),
            children: [
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                //Some(Element::Leaf(Default::default())),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(Some(Element::Leaf(Default::default()))),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                NodeKind::Raw(None),
                //Some(Element::Leaf(Default::default())),
                NodeKind::Raw(None),
            ],
        };

        let expected_bitmap: [u8; 2] = [0b00000000, 0b00000001];
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
                vec![0b01111111, 0],
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
                vec![0b00111111, 0],
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
            let out = leaf.encoded_header(V0);
            assert_eq!(out, expected_enc_header);
        }

        let branches = vec![
            (
                V0,
                Branch::<Blake256Hasher> {
                    partial_key: Key(vec![0, 1, 2]),
                    children: Default::default(),
                    storage_value: VersionedStorageValue::RawStorageValue(None),
                },
                vec![0b10000011],
            ),
            (
                V0,
                Branch::<Blake256Hasher> {
                    partial_key: Key([0; 63].to_vec()),
                    children: Default::default(),
                    storage_value: VersionedStorageValue::RawStorageValue(Some(vec![1, 2, 3])),
                },
                vec![0b11111111, 0],
            ),
            (
                V0,
                Branch::<Blake256Hasher> {
                    partial_key: Key([0; 319].to_vec()),
                    children: Default::default(),
                    storage_value: VersionedStorageValue::HashedStorageValue([0; 32]),
                },
                vec![0b00011111, 0b11111111, 0b00110001],
            ),
            (
                V1,
                Branch::<Blake256Hasher> {
                    partial_key: Key([1, 2, 3].to_vec()),
                    children: Default::default(),
                    storage_value: VersionedStorageValue::RawStorageValue(Some(vec![0; 33])),
                },
                vec![0b00010011],
            ),
        ];

        for (versio, branch, expected_enc_header) in branches {
            let out = branch.encoded_header(versio);
            assert_eq!(out, expected_enc_header)
        }
    }

    #[test]
    fn test_trie_encoding_v0() {
        let mut t = Trie::<Blake256Hasher> {
            root: Default::default(),
        };

        t.insert(Key::new(b"a"), Some([0; 40].to_vec())).unwrap();
        t.insert(Key::new(b"al"), Some([0; 40].to_vec())).unwrap();
        t.insert(Key::new(b"alfa"), Some([0; 40].to_vec())).unwrap();

        let expected_hash =
            hex!("df1012a786cddcdfa4a8cf015e873677bc2e7a3c8b3579d9bae93117cbcfb7c1");
        let root_hash = t.root_hash(V0).unwrap();

        assert_eq!(expected_hash.to_vec(), root_hash);
    }

    #[test]
    fn test_trie_decode_leaf() {
        let mut t = Trie::<Blake256Hasher> {
            root: Default::default(),
        };

        t.insert(Key::new(b"a"), Some([0; 40].to_vec())).unwrap();
        let prev_hash = t.root_hash(V0);

        let mut recorder = InMemoryRecorder::new();
        let mut encoded_iter = t.encode_trie_root(V0, &mut recorder).unwrap();

        let decoded_node =
            codec::decode_node::<Blake256Hasher>(&mut encoded_iter, &recorder).unwrap();

        let trie_after_decoding = Trie::<Blake256Hasher> { root: decoded_node };
        let next_hash = trie_after_decoding.root_hash(V0);
        assert_eq!(prev_hash, next_hash);
    }

    #[test]
    fn test_trie_decode_leaf_with_hashed_value() {
        let mut t = Trie::<Blake256Hasher> {
            root: Default::default(),
        };

        t.insert(Key::new(b"a"), Some([0; 40].to_vec())).unwrap();
        let prev_hash = t.root_hash(V1);

        let mut recorder = InMemoryRecorder::new();
        let mut encoded_iter = t.encode_trie_root(V1, &mut recorder).unwrap();
        let decoded_node =
            codec::decode_node::<Blake256Hasher>(&mut encoded_iter, &recorder).unwrap();

        let trie_after_decoding = Trie::<Blake256Hasher> { root: decoded_node };
        let next_hash = trie_after_decoding.root_hash(V1);
        assert_eq!(prev_hash, next_hash);
    }

    #[test]
    fn test_trie_decode_with_branches_v0() {
        let mut t = Trie::<Blake256Hasher> {
            root: Default::default(),
        };

        t.insert(Key::new(b"a"), Some([0; 40].to_vec())).unwrap();
        t.insert(Key::new(b"al"), Some([0; 40].to_vec())).unwrap();
        t.insert(Key::new(b"alpha"), Some([0; 40].to_vec()))
            .unwrap();

        let prev_hash = t.root_hash(V0);

        let mut recorder = InMemoryRecorder::new();

        let mut encoded_iter = t.encode_trie_root(V0, &mut recorder).unwrap();

        let decoded_node =
            codec::decode_node::<Blake256Hasher>(&mut encoded_iter, &recorder).unwrap();

        let trie_after_decoding = Trie::<Blake256Hasher> { root: decoded_node };
        let next_hash = trie_after_decoding.root_hash(V0);
        assert_eq!(prev_hash, next_hash);
    }

    #[test]
    fn test_trie_decode_with_branches_v1() {
        let mut t = Trie::<Blake256Hasher> {
            root: Default::default(),
        };

        t.insert(Key::new(b"keynumber1"), Some([0; 32].to_vec()))
            .unwrap();
        t.insert(Key::new(b"keynum"), Some([0; 59].to_vec()))
            .unwrap();
        t.insert(Key::new(b"k"), Some([0; 10].to_vec())).unwrap();
        t.insert(Key::new(b"iota"), Some([0; 100].to_vec()))
            .unwrap();

        let prev_hash = t.root_hash(V1);

        let mut recorder = InMemoryRecorder::new();
        let mut encoded_iter = t.encode_trie_root(V1, &mut recorder).unwrap();

        let decoded_node =
            codec::decode_node::<Blake256Hasher>(&mut encoded_iter, &recorder).unwrap();

        let trie_after_decoding = Trie::<Blake256Hasher> { root: decoded_node };
        let next_hash = trie_after_decoding.root_hash(V1);
        assert_eq!(prev_hash, next_hash);
    }
}
