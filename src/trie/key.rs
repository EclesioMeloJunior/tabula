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

        let padded_nibbles = if (self.0.len() % 2) != 0 {
            let mut padded = vec![0];
            padded.extend(self.0);
            padded
        } else {
            self.0
        };

        let mut key = Vec::new();
        for i in (0..padded_nibbles.len()).step_by(2) {
            let byte = (padded_nibbles[i] << 4) | padded_nibbles[i + 1];
            key.push(byte)
        }

        key
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

    pub fn as_bytes(&self) -> Vec<u8> {
        self.clone().into()
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
        if (index + 1) > self.0.len() {
            return (at, None);
        }
        (at, Some(Key(self.0.as_slice()[(index + 1)..].to_vec())))
    }

    // new_partial_key returns a new instance of Key starting from index 0..lim
    pub fn new_partial_key(&self, lim: usize) -> Key {
        Key(self.0.as_slice()[0..lim].to_vec())
    }

    pub fn encode_len(&self, variant: u8, remaining: u8) -> Vec<u8> {
        let mut length = self.0.len();

        if length < (remaining as usize) {
            let encoded = variant | (length as u8);
            return encoded.to_le_bytes().to_vec();
        }

        let mut encoded = vec![variant | remaining];
        length -= remaining as usize;

        loop {
            if length > (u8::MAX as usize) {
                encoded.push(255);
                length -= 255;
                continue;
            }

            encoded.push(length as u8);
            break;
        }

        encoded
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
