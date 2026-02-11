use cryptec_core::{Mnemonic, BdkWallet};
use std::env;
use serde_json::json;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cryptec_cli <cmd> [args]");
        std::process::exit(1);
    }
    let cmd = &args[1];
    match cmd.as_str() {
        "gen-mnemonic" => {
            let m = Mnemonic::generate(128);
            println!("{}", m.phrase);
        }
        "bdk-new-addr" => {
            let phrase = if args.len() > 2 { args[2].clone() } else { Mnemonic::generate(128).phrase };
            let w = BdkWallet::new_from_mnemonic(&phrase, "", bitcoin::Network::Testnet).expect("create wallet");
            let addr = w.get_new_address().expect("addr");
            println!("{}", addr);
        }
        "version" => {
            let v = json!({"name":"cryptec_cli","version":"0.1.0"});
            println!("{}", v.to_string());
        }
        _ => {
            eprintln!("unknown command");
            std::process::exit(2);
        }
    }
}
