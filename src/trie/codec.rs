use std::{iter, mem};

use super::*;
use parity_scale_codec::{Decode, Input};

pub type CodecError = parity_scale_codec::Error;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NodeKind {
    Leaf,
    LeafWithHashed,
    Branch,
    BranchWithValue,
    BranchWithHashed,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DecodeError {
    EmptyEncodedBytes,
    UnexpectedEncodedEOF,
    UnexpectedHeaderBytes,
    FailToGetPartialKeyByte,
    ExpectedHashedFoundEmpty,
    FailToGetChildrenBitmapByte,
    EncodedChildNotRecorded,
}

pub struct EncodedIter {
    pub iter: IntoIter<u8>,
}

impl Default for EncodedIter {
    fn default() -> Self {
        EncodedIter {
            iter: vec![].into_iter(),
        }
    }
}

impl EncodedIter {
    pub fn new(iter: IntoIter<u8>) -> Self {
        EncodedIter { iter }
    }

    pub fn hash<H: Hasher>(&mut self) -> H::Out {
        let mut encoded_iter = mem::take(self);
        let encoded: Vec<u8> = encoded_iter.iter.collect();
        H::hash(&encoded)
    }
}

impl Input for EncodedIter {
    fn read(&mut self, into: &mut [u8]) -> Result<(), CodecError> {
        if into.len() > self.iter.len() {
            return Err("Not enough data to fill buffer".into());
        }

        for idx in 0..into.len() {
            if let Some(v) = self.iter.next() {
                into[idx] = v
            } else {
                return Err("Failed to read iterator".into());
            }
        }

        Ok(())
    }

    fn remaining_len(&mut self) -> Result<Option<usize>, CodecError> {
        Ok(Some(self.iter.len()))
    }
}

fn decode_header(header_byte: u8) -> (NodeKind, u8) {
    match header_byte & 0b11110000 {
        0b01000000 => (NodeKind::Leaf, 0b00111111),
        0b10000000 => (NodeKind::Branch, 0b00111111),
        0b11000000 => (NodeKind::BranchWithValue, 0b00111111),
        0b00100000 => (NodeKind::LeafWithHashed, 0b00011111),
        0b00010000 => (NodeKind::BranchWithHashed, 0b00001111),
        _ => unreachable!(),
    }
}

fn decode_partial_key_length(encoded: &mut EncodedIter, header: u8, pk_len_mask: u8) -> u32 {
    let mut partial_len: u32 = (header & pk_len_mask) as u32;
    if partial_len == (pk_len_mask as u32) || partial_len == 255 {
        while let Some(current_byte) = encoded.iter.next() {
            let value = current_byte.clone();
            if value == 0 {
                break;
            }
            partial_len = partial_len.saturating_add(value as u32);
        }
    }

    partial_len
}

fn decode_element<H>(
    encoded: &mut EncodedIter,
    node_kind: NodeKind,
    pk_len: u32,
    recorder: &NodeRecorder,
) -> Result<Element<H>, DecodeError>
where
    H: Hasher,
{
    let actual_key_len = (pk_len / 2 + pk_len % 2) as usize;
    let mut encoded_partial_key: Vec<u8> = vec![0; actual_key_len];
    encoded.read(&mut encoded_partial_key).unwrap();

    let mut partial_key = Key::new(&encoded_partial_key);
    if pk_len % 2 == 1 {
        partial_key.0.remove(0);
    }

    match node_kind {
        NodeKind::Leaf => {
            let decoded = Vec::<u8>::decode(encoded).unwrap();
            let storage_value = if decoded.len() > 0 {
                VersionedStorageValue::RawStorageValue(Some(decoded))
            } else {
                VersionedStorageValue::RawStorageValue(None)
            };

            let leaf = Leaf::<H> {
                partial_key,
                storage_value,
            };

            Ok(Element::Leaf(leaf))
        }
        NodeKind::LeafWithHashed => {
            let mut hashed_value: [u8; 32] = Default::default();
            let hashed_value = match encoded.read(&mut hashed_value) {
                Err(_) => return Err(DecodeError::ExpectedHashedFoundEmpty),
                Ok(()) => H::Out::try_from(hashed_value.to_vec()).unwrap(),
            };

            Ok(Element::Leaf(Leaf::<H> {
                partial_key,
                storage_value: VersionedStorageValue::HashedStorageValue(hashed_value),
            }))
        }
        _ => {
            let mut child_bitmap: [u8; 2] = Default::default();
            for idx in 0..2 {
                if let Some(byte) = encoded.iter.next() {
                    child_bitmap[idx] = byte.clone()
                } else {
                    return Err(DecodeError::FailToGetChildrenBitmapByte);
                }
            }

            let mut child_bitmap = u16::from_le_bytes(child_bitmap);
            let mut has_child_at: [bool; 16] = Default::default();
            for idx in (0..).take(16) {
                if child_bitmap == 0 {
                    break;
                }

                if (child_bitmap & 1) == 1 {
                    has_child_at[idx as usize] = true;
                }

                child_bitmap >>= 1
            }

            let storage_value = match node_kind {
                NodeKind::Branch => VersionedStorageValue::RawStorageValue(None),
                NodeKind::BranchWithValue => {
                    let decoded = Vec::<u8>::decode(encoded).unwrap();
                    VersionedStorageValue::RawStorageValue(Some(decoded))
                }
                NodeKind::BranchWithHashed => {
                    let mut hashed_value: [u8; 32] = Default::default();
                    let hashed_value = match encoded.read(&mut hashed_value) {
                        Err(_) => return Err(DecodeError::ExpectedHashedFoundEmpty),
                        Ok(()) => H::Out::try_from(hashed_value.to_vec()).unwrap(),
                    };
                    VersionedStorageValue::HashedStorageValue(hashed_value)
                }
                _ => unreachable!("should only handle branch kinds"),
            };

            let mut children: [Option<Element<H>>; 16] = Default::default();
            for idx in (0..).take(16) {
                if !has_child_at[idx] {
                    continue;
                }

                let encode_child = {
                    let encoded_child = Vec::<u8>::decode(encoded).unwrap();
                    if encoded_child.len() < 32 {
                        encoded_child
                    } else {
                        if let Some(encoded_child) = recorder.get(&encoded_child).unwrap() {
                            encoded_child.clone()
                        } else {
                            return Err(DecodeError::EncodedChildNotRecorded);
                        }
                    }
                };

                let mut encoded_child_iter = EncodedIter::new(encode_child.into_iter());
                let decoded_node = decode_node(&mut encoded_child_iter, recorder).unwrap();
                assert_eq!(encoded_child_iter.remaining_len(), Ok(Some(0)));
                children[idx] = decoded_node;
            }

            let branch = Branch {
                children,
                partial_key,
                storage_value,
            };

            Ok(Element::Branch(Box::new(branch)))
        }
    }
}

pub fn decode_node<H>(
    encoded: &mut EncodedIter,
    recorder: &NodeRecorder,
) -> Result<Option<Element<H>>, DecodeError>
where
    H: Hasher,
{
    if let Some(header) = encoded.iter.next() {
        let (node_kind, pk_len_mask) = decode_header(header);
        let pk_len = decode_partial_key_length(encoded, header, pk_len_mask);
        let node = decode_element(encoded, node_kind, pk_len, recorder)?;

        assert_eq!(encoded.remaining_len(), Ok(Some(0)));
        return Ok(Some(node));
    }

    Ok(None)
}
