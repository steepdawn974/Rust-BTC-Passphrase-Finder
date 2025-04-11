use bitcoin::secp256k1::Secp256k1;
use bip39::{Mnemonic, Language};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use memmap::Mmap;
use std::sync::Arc;
use log::{warn, info};
use std::fs::File;
use std::str::FromStr;
use bitcoin::util::bip32::{ExtendedPrivKey, DerivationPath};
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::Script;
use crate::config::Config;
use rust_btc_passphrase_finder::wordlist;
use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};

/// Process a single wordlist file to find the matching passphrase
/// 
/// # Arguments
/// * `file_path` - Path to the wordlist file
/// * `config` - Reference to the configuration
/// * `passphrase_found` - Atomic flag indicating if passphrase was found
/// * `address_format` - Format of the target address
/// * `multi_progress` - Multi-progress bar for tracking progress
/// 
/// # Returns
/// * `io::Result<()>` - Success or IO error
fn process_wordlist_file(
    file_path: &std::path::Path,
    config: &Arc<Config>,
    passphrase_found: &Arc<AtomicBool>,
    address_format: &str,
    multi_progress: &MultiProgress,
) -> io::Result<()> {
    info!("Processing file: {}", file_path.display());
    
    println!("Opening file: {}", file_path.display());
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            println!("Error opening file {}: {}", file_path.display(), e);
            return Err(e);
        }
    };

    let metadata = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            println!("Error getting metadata for {}: {}", file_path.display(), e);
            return Err(e);
        }
    };

    if metadata.len() == 0 {
        println!("File {} is empty, skipping", file_path.display());
        return Ok(());
    }

    println!("File metadata: size={} bytes", metadata.len());
    let mmap = match unsafe { Mmap::map(&file) } {
        Ok(m) => m,
        Err(e) => {
            println!("Error memory mapping {}: {}", file_path.display(), e);
            return Err(e);
        }
    };
    let lines: Vec<&str> = mmap.split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| std::str::from_utf8(line).map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid UTF-8")))
        .collect::<Result<Vec<&str>, io::Error>>()?;
    
    // Create a progress bar for this file
    let pb = multi_progress.add(ProgressBar::new(lines.len() as u64));
    pb.set_style(ProgressStyle::default_bar()
        .template(&format!("{} {{spinner:.green}} [{{elapsed_precise}}] [{{bar:40.cyan/blue}}] {{pos}}/{{len}} ({{eta}})", 
                         file_path.file_name().unwrap().to_string_lossy()))
        .progress_chars("#>-"));
    
    // Create a custom thread pool
    let pool = ThreadPoolBuilder::new().num_threads(config.num_threads).build()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
    
    // Perform parallel processing within the custom thread pool
    pool.install(|| {
        lines.par_iter().for_each(|&passphrase| {
            if !passphrase_found.load(Ordering::Relaxed) {
                let mnemonic = Mnemonic::parse_in(Language::English, &config.seed_phrase)
                    .expect("Failed to create mnemonic");
                let seed = mnemonic.to_seed(passphrase);
                let secp = Secp256k1::new();
                let root_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed)
                    .expect("Failed to create root key");

                // Define the derivation paths
                let derivation_paths: Vec<DerivationPath> = match address_format {
                    "legacy" => (0..config.address_paths_to_search)
                        .map(|i| DerivationPath::from_str(&format!("m/44'/0'/0'/0/{}", i))
                            .expect("Failed to create derivation path"))
                        .collect(),
                    "p2sh" => (0..config.address_paths_to_search)
                        .map(|i| DerivationPath::from_str(&format!("m/49'/0'/0'/0/{}", i))
                            .expect("Failed to create derivation path"))
                        .collect(),
                    "segwit" => (0..config.address_paths_to_search)
                        .map(|i| DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", i))
                            .expect("Failed to create derivation path"))
                        .collect(),
                    "p2wsh" => (0..config.address_paths_to_search)
                        .map(|i| DerivationPath::from_str(&format!("m/48'/0'/0'/2/{}", i))
                            .expect("Failed to create derivation path"))
                        .collect(),
                    _ => panic!("Unsupported address format"),
                };

                for derivation_path in derivation_paths {
                    let derived_key = root_key.derive_priv(&secp, &derivation_path)
                        .expect("Failed to derive key");

                    let address = match address_format {
                        "legacy" => {
                            let pubkey = bitcoin::PublicKey {
                                compressed: true,
                                inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key.private_key),
                            };
                            Address::p2pkh(&pubkey, Network::Bitcoin)
                        },
                        "p2sh" => {
                            let pubkey = bitcoin::PublicKey {
                                compressed: true,
                                inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key.private_key),
                            };
                            Address::p2shwpkh(&pubkey, Network::Bitcoin)
                                .expect("Failed to create P2SH address")
                        },
                        "segwit" => {
                            let pubkey = bitcoin::PublicKey {
                                compressed: true,
                                inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key.private_key),
                            };
                            Address::p2wpkh(&pubkey, Network::Bitcoin)
                                .expect("Failed to create SegWit address")
                        },
                        "p2wsh" => {
                            let pubkey = bitcoin::PublicKey {
                                compressed: true,
                                inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key.private_key),
                            };
                            let wpkh = pubkey.wpubkey_hash().expect("Failed to create WPubkeyHash");
                            let script = Script::new_v0_p2wpkh(&wpkh);
                            Address::p2wsh(&script, Network::Bitcoin)
                        },
                        _ => panic!("Unsupported address format"),
                    };

                    if address.to_string() == config.expected_address {
                        println!("\n===============================");
                        println!("🎉 HURRA! Passphrase found! 🎉");
                        println!("===============================");
                        println!("🔑 Passphrase: {}", passphrase);
                        println!("📬 Address format: {}", address_format);
                        println!("===============================");
                        println!("✨ If you found my program helpful, I would greatly appreciate a donation via Bitcoin Lightning!");
                        println!("⚡ Lightning address: aldobarazutti@getalby.com");
                        println!("🙏 Thank you very much!");
                        println!("📬 If you want to contact me, you can find me on Nostr!");
                        println!("🔗 npub: npub1hht9umpeet75w55uzs9lq6ksayfpcvl9lk64hye75j0yj4husq5ss8xsry");
                        println!("===============================");
                        passphrase_found.store(true, Ordering::SeqCst);
                        std::process::exit(0);
                    }
                }
            }
            pb.inc(1);
        });
    });
    
    pb.finish();
    Ok(())
}

/// Get the format of the target address
fn get_address_format(address: &str) -> &str {
    if address.starts_with("1") {
        "legacy"
    } else if address.starts_with("3") {
        "p2sh"
    } else if address.starts_with("bc1q") && address.len() == 42 {
        "segwit"
    } else if address.starts_with("bc1q") && address.len() > 42 {
        "p2wsh"
    } else {
        panic!("Unsupported address format");
    }
}

/// Find a passphrase that generates the target Bitcoin address
/// 
/// This function searches through multiple wordlist files in parallel, looking for
/// a passphrase that generates the target Bitcoin address.
/// 
/// # Arguments
/// * `config` - Configuration containing search parameters and paths
/// 
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error
/// Find a passphrase that generates the target Bitcoin address
pub fn find_passphrase(config: &Arc<Config>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting find_passphrase function (by address)");
    println!("Config wordlist_path: {}", &config.wordlist_path);
    // Determine the address format
    let address_format = get_address_format(&config.expected_address);
    println!("Address format: {}", address_format);

    // Get list of wordlist files
    println!("Looking for wordlist files in: {}", &config.wordlist_path);
    let wordlist_files = match wordlist::get_wordlist_files(&config.wordlist_path) {
        Ok(files) => {
            println!("Found {} wordlist files", files.len());
            files
        },
        Err(e) => {
            println!("Error getting wordlist files: {}", e);
            return Err(e.into());
        }
    };
    if wordlist_files.is_empty() {
        return Err("No wordlist files found. Run 'Generate Passphrases' first.".into());
    }

    println!("Found {} wordlist files to process", wordlist_files.len());

    // Create a multi-progress bar for tracking all files
    let multi_progress = MultiProgress::new();

    // Flag to check if passphrase is found
    let passphrase_found = Arc::new(AtomicBool::new(false));

    // Process each wordlist file
    for file_path in wordlist_files.iter() {
        if passphrase_found.load(Ordering::Relaxed) {
            break;
        }

        process_wordlist_file(
            &file_path,
            config,
            &passphrase_found,
            address_format,
            &multi_progress,
        )?;
    }

    // MultiProgress will be cleaned up when dropped

    // Check if passphrase was found
    if !passphrase_found.load(Ordering::SeqCst) {
        warn!("Passphrase not found in any wordlist file.");
        println!("\n===============================");
        println!("⚠️ Oops! Passphrase not found ⚠️");
        println!("===============================");
        println!("📬 Address format: {}", address_format);
        println!("===============================");
    }

    Ok(())
}