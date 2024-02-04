use std::fmt::Debug;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

pub trait Hasher: Clone + Debug {
    type Out: Debug + PartialEq + Clone;

    fn hash(input: &[u8]) -> Self::Out;
}

#[derive(Default, Debug, PartialEq, Clone)]
pub struct Blake256Hasher;
impl Hasher for Blake256Hasher {
    type Out = [u8; 32];

    fn hash(input: &[u8]) -> Self::Out {
        let mut hasher = Blake2bVar::new(32).unwrap();
        hasher.update(input);
        let mut buf = [0u8; 32];
        hasher.finalize_variable(&mut buf).unwrap();
        buf
    }
}
