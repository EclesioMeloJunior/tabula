use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub bootnodes: Vec<String>,
    pub chain_spec: String,
}

pub mod genesis {
    use serde::Deserialize;
    use std::collections::HashMap;

    #[derive(Debug, Deserialize, Clone)]
    pub struct GenesisRaw {
        pub top: HashMap<String, String>,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct Genesis {
        pub raw: GenesisRaw,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct RawChainSpec {
        pub name: String,
        pub id: String,
        #[serde(alias = "bootNodes")]
        pub bootnodes: Vec<String>,
        #[serde(alias = "protocolId")]
        pub protocol_id: String,
        #[serde(alias = "forkBlocks")]
        pub fork_blocks: Option<Vec<String>>,
        #[serde(alias = "badBlocks")]
        pub bad_blocks: Option<Vec<String>>,
        pub genesis: Genesis,
    }
}

pub mod parser {
    use super::{genesis, ServerConfig};
    use serde::de::DeserializeOwned;

    pub trait ParserFromStr {
        type Output: DeserializeOwned;
        fn from_str(input: &'_ str) -> Self::Output;
    }

    pub struct ConfigTOMLParser;
    impl ParserFromStr for ConfigTOMLParser {
        type Output = ServerConfig;
        fn from_str(input: &str) -> Self::Output {
            toml::from_str::<Self::Output>(input).expect("failed to parse toml file")
        }
    }

    #[derive(Debug, Clone)]
    pub struct RawChainSpecJSONParser;
    impl ParserFromStr for RawChainSpecJSONParser {
        type Output = genesis::RawChainSpec;
        fn from_str(input: &'_ str) -> Self::Output {
            serde_json::from_str(input).expect("failed to parse raw chain spec file")
        }
    }
}

pub fn from_file<P: parser::ParserFromStr>(path: String) -> P::Output {
    let contents = fs::read(path).expect("failed to read file");
    let str_contents = String::from_utf8_lossy(&contents);

    P::from_str(&str_contents)
}
