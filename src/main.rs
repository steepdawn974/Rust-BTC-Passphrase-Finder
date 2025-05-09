mod generate_address;
mod find_passphrase;
mod find_taproot_passphrase;
mod config;
mod passphrase_generater;
mod regex_parser;
mod find_passphrase_by_fingerprint;
mod state;

use find_passphrase::find_passphrase;
use generate_address::generate_all_addresses;
use find_taproot_passphrase::find_taproot_passphrase;
use config::Config;
use passphrase_generater::generate_and_save_passphrases;
use dialoguer::{theme::ColorfulTheme, Select};
use std::sync::Arc;
use simplelog::{Config as LogConfig, LevelFilter, SimpleLogger};
use find_passphrase_by_fingerprint::find_passphrase_by_fingerprint;

fn get_address_format(address: &str) -> &str {
    if address.starts_with("1") {
        "legacy"
    } else if address.starts_with("3") {
        "p2sh"
    } else if address.starts_with("bc1q") && address.len() == 42 {
        "segwit"
    } else if address.starts_with("bc1q") && address.len() > 42 {
        "p2wsh"
    } else if address.starts_with("bc1p") {
        "taproot"
    } else {
        panic!("Unsupported address format");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    SimpleLogger::init(LevelFilter::Debug, LogConfig::default())?;

    // Read and deserialize the configuration
    let config_str = std::fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_str)?;
    let config = Arc::new(config);

    // Create a menu
    let items = vec![
        "Generate Addresses",
        "Find Passphrase (by address)",
        "Find Passphrase (by master fingerprint)",
        "Generate Passphrases",
    ];
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an option")
        .default(0)
        .items(&items)
        .interact()?;

    match selection {
        0 => generate_all_addresses().unwrap_or_else(|e| eprintln!("Error: {}", e)),
        1 => {
            let address_format = get_address_format(&config.expected_address);
            if address_format == "taproot" {
                find_taproot_passphrase(&config).unwrap_or_else(|e| eprintln!("Error: {}", e));
            } else {
                find_passphrase(&config).unwrap_or_else(|e| eprintln!("Error: {}", e));
            }
        },
        2 => find_passphrase_by_fingerprint(&config).unwrap_or_else(|e| eprintln!("Error: {}", e)),
        3 => generate_and_save_passphrases(&config).unwrap_or_else(|e| eprintln!("Error: {}", e)),
        _ => println!("Invalid selection"),
    }

    Ok(())
}