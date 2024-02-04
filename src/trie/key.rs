use std::convert::{From, Into};

pub type Nibble = u8;

#[derive(Default, Debug, PartialEq, Clone)]
pub struct Key(pub Vec<Nibble>);

impl From<Vec<(Nibble, Nibble)>> for Key {
    fn from(encoded_nibbles: Vec<(Nibble, Nibble)>) -> Self {
        let expanded_nibbles = encoded_nibbles
            .into_iter()
            .map(|(fst, snd): (Nibble, Nibble)| vec![fst, snd])
            .flatten()
            .collect::<Vec<Nibble>>();

        Key(expanded_nibbles)
    }
}

impl Into<Vec<u8>> for Key {
    fn into(self) -> Vec<u8> {
        if self.0.len() == 0 {
            return vec![];
        }

        self.0
            .chunks(2)
            .into_iter()
            .map(|chks| (chks[0] << 4 & 0xf0) | (chks[1] & 0x0f))
            .collect::<Vec<u8>>()
    }
}

impl Key {
    pub fn new(input: &[u8]) -> Self {
        let nibbles = input
            .into_iter()
            .map(|b| {
                let fst: Nibble = b >> 4;
                let snd: Nibble = b ^ (fst << 4);
                (fst, snd)
            })
            .collect::<Vec<(Nibble, Nibble)>>();

        Key::from(nibbles)
    }

    pub fn common_length(&self, other: &Key) -> usize {
        self.0
            .iter()
            .zip(other.0.iter())
            .take_while(|(fst, snd)| (fst == snd))
            .count()
    }

    // given an index it will return
    pub fn child_index(&self, index: usize) -> (Option<&Nibble>, Option<Key>) {
        if index > self.0.len() {
            return (None, None);
        }

        let at = self.0.get(index);
        if index + 1 > self.0.len() {
            return (at, None);
        }
        (at, Some(Key(self.0.as_slice()[index + 1..].to_vec())))
    }
}

#[cfg(test)]
mod tests {
    use super::Key;
    use hex_literal::hex;

    #[test]
    fn test_empty_input_key_encoding() {
        let encoded = Key::new(&vec![]);
        let expected = Key::from(vec![]);
        assert_eq!(expected, encoded);
    }

    #[test]
    fn test_input_key_encoding() {
        let input = hex!("aabbcc");
        let encoded = Key::new(&input);
        assert_eq!(encoded, Key(vec![0x0a, 0x0a, 0x0b, 0x0b, 0x0c, 0x0c]));

        let back_to_bytes: Vec<u8> = encoded.into();
        assert_eq!(input.to_vec(), back_to_bytes);
    }

    #[test]
    fn test_common_length() {
        let tests: Vec<(Key, Key)> = vec![
            (Key(vec![]), Key(vec![])),
            (
                Key(vec![0x0a, 0x0a, 0x0b, 0x0b, 0x0c, 0x0c]),
                Key(vec![0x0a, 0x0a]),
            ),
            (
                Key(vec![0x0a, 0x0a, 0x0b, 0x0b, 0x0c, 0x0c]),
                Key(vec![0x0a, 0x0a, 0x0b, 0x0b, 0x0c, 0x0c]),
            ),
            (Key(vec![]), Key(vec![0x0a, 0x0a])),
        ];

        let expected_len: Vec<usize> = vec![0, 2, 6, 0];

        let cases = tests.iter().zip(expected_len);
        for (test, expected) in cases {
            let output = test.0.common_length(&test.1);
            assert_eq!(output, expected);
        }
    }
}
