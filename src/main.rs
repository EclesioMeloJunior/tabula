mod config;

use std::error::Error;
use std::thread;
use std::time::Duration;
use tokio::task;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");
    let server = build_simple_node();
    let server_handle = task::spawn(async move { server.run().await });

    server_handle.await.unwrap();
    println!("server handle shuted down!");
    Ok(())
}

#[derive(Clone)]
struct PolkaniteServer {
    bootnodes: Vec<String>,
}

impl PolkaniteServer {
    async fn run(&self) {
        println!("Polkanite started");
        println!("{:?}", self.bootnodes);
        thread::sleep(Duration::from_millis(5000));
        println!("Polkanite finished");
    }
}

fn build_simple_node() -> PolkaniteServer {
    let server_settings =
        config::config_from_file::<config::parser::TomlParser>(String::from("./config/wnd.toml"));
    PolkaniteServer {
        bootnodes: server_settings.bootnodes.clone(),
    }
}
