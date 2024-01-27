use serde::Deserialize;
use std::fs;
use toml;

#[derive(Deserialize)]
pub struct ServerConfig {
    pub bootnodes: Vec<String>,
}

pub mod parser {
    use super::ServerConfig;
    use serde::de::DeserializeOwned;

    pub trait ParserFromSlice {
        type Output: DeserializeOwned;
        fn from_str(input: &'_ str) -> Self::Output;
    }

    pub struct TomlParser;
    impl ParserFromSlice for TomlParser {
        type Output = ServerConfig;
        fn from_str(input: &str) -> Self::Output {
            toml::from_str::<Self::Output>(input).expect("failed to parse toml file")
        }
    }
}

// config_from_file::<TomlParser>("path_to.toml")
pub fn config_from_file<P: parser::ParserFromSlice>(path: String) -> P::Output {
    let contents = fs::read(path).expect("failed to read file");
    let str_contents = String::from_utf8_lossy(&contents);

    P::from_str(&str_contents)
}
