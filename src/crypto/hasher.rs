use parity_scale_codec::Encode;
use std::fmt::Debug;

pub trait Hasher: Clone + Debug {
    type Out: Debug + PartialEq + Clone + Encode + Into<Vec<u8>>;

    fn hash(input: &[u8]) -> Self::Out;
}

#[derive(Default, Debug, PartialEq, Clone)]
pub struct Blake256Hasher;
impl Hasher for Blake256Hasher {
    type Out = [u8; 32];

    fn hash(input: &[u8]) -> Self::Out {
        blake2b_simd::Params::new()
            .hash_length(32)
            .hash(input)
            .as_bytes()
            .try_into()
            .expect("slice is always the necessary length")
    }
}
