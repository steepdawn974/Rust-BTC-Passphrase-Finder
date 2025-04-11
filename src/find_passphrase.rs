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
use crate::state::{State, ProcessingStatus};
use rust_btc_passphrase_finder::wordlist;
use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;

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
    state: &mut State,
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
                        // Clear progress bar before printing the success message
                        pb.finish_and_clear();
                        
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
                        
                        // We need to update the state before exiting
                        passphrase_found.store(true, Ordering::SeqCst);
                        
                        // Clone the expected_address for use in the thread
                        let expected_address = config.expected_address.clone();
                        
                        // Create a channel to communicate the match information back to the main thread
                        let (tx, rx) = std::sync::mpsc::channel();
                        let match_info = (file_path.to_path_buf(), passphrase.to_string());
                        
                        // Send the match information through the channel
                        if let Err(e) = tx.send(match_info) {
                            warn!("Failed to send match info: {}", e);
                        }
                        
                        // Write to the temporary file as a backup
                        let match_info_str = format!("{},{}", file_path.display(), passphrase);
                        if let Err(e) = std::fs::write("match_found.tmp", match_info_str) {
                            warn!("Failed to write match info: {}", e);
                        }
                        
                        // Update the state in a separate thread to avoid deadlocks
                        std::thread::spawn(move || {
                            // Load the current state
                            if let Ok(mut state) = State::load_or_create(&expected_address) {
                                // Get the match information
                                if let Ok((file_path, passphrase)) = rx.recv() {
                                    // Update the state with the file info
                                    if let Err(e) = state.update_file_info(&file_path, ProcessingStatus::MatchFound) {
                                        warn!("Failed to update state file info: {}", e);
                                    }
                                    
                                    // Update the state with the found passphrase
                                    state.update_found_passphrase(&passphrase);
                                    
                                    // Save the state
                                    if let Err(e) = state.save(&State::get_state_file_path()) {
                                        warn!("Failed to save state: {}", e);
                                    }
                                }
                            }
                            
                            // Exit after updating the state
                            std::process::exit(0);
                        });
                        
                        // Wait a moment to allow the state update thread to start
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
            pb.inc(1);
        });
    });
    
    pb.finish_with_message("Done");
    
    // Check if a passphrase was found
    if passphrase_found.load(Ordering::Relaxed) {
        // Update state to mark file as containing a match
        if let Err(e) = state.update_file_info(file_path, ProcessingStatus::MatchFound) {
            warn!("Failed to update state: {}", e);
        }
    } else {
        // Update state to mark file as processed with no match
        if let Err(e) = state.update_file_info(file_path, ProcessingStatus::Processed) {
            warn!("Failed to update state: {}", e);
        }
    }
    
    // Save the state
    if let Err(e) = state.save(&State::get_state_file_path()) {
        warn!("Failed to save state: {}", e);
    }
    
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
    
    // Check if there was a previous match that didn't get properly recorded in the state
    let match_file = Path::new("match_found.tmp");
    if match_file.exists() {
        println!("Found previous match information");
        let match_info = std::fs::read_to_string(match_file)?;
        let parts: Vec<&str> = match_info.split(',').collect();
        
        if parts.len() >= 2 {
            let file_path = Path::new(parts[0]);
            let passphrase = parts[1];
            
            println!("Previous match found in file: {}", file_path.display());
            println!("Passphrase: {}", passphrase);
            
            // Initialize or load state
            let mut state = match State::load_or_create(&config.expected_address) {
                Ok(state) => state,
                Err(e) => {
                    warn!("Failed to load state: {}", e);
                    State::new(&config.expected_address)
                }
            };
            
            // Update state with the match file info
            if let Err(e) = state.update_file_info(file_path, ProcessingStatus::MatchFound) {
                warn!("Failed to update state file info: {}", e);
            }
            
            // Update state with the found passphrase
            state.update_found_passphrase(passphrase);
            
            // Save the state
            if let Err(e) = state.save(&State::get_state_file_path()) {
                warn!("Failed to save state: {}", e);
            }
            
            // Remove the temporary file
            if let Err(e) = std::fs::remove_file(match_file) {
                warn!("Failed to remove match file: {}", e);
            }
            
            // Display the match information
            println!("\n===============================");
            println!("🎉 MATCH FOUND! 🎉");
            println!("===============================");
            println!("🔑 Passphrase: {}", passphrase);
            println!("🔍 Address: {}", config.expected_address);
            println!("===============================");
            
            return Ok(());
        }
    }
    
    // Initialize or load state
    let mut state = match State::load_or_create(&config.expected_address) {
        Ok(state) => {
            println!("Loaded existing state file");
            state
        },
        Err(e) => {
            warn!("Failed to load state: {}", e);
            println!("Creating new state file");
            State::new(&config.expected_address)
        }
    };
    
    // First check if the seed phrase without any passphrase matches the expected address
    let mnemonic = Mnemonic::parse_in(Language::English, &config.seed_phrase)
        .expect("Failed to create mnemonic");
    let seed = mnemonic.to_seed(""); // Empty passphrase
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
        _ => panic!("Unsupported address format: {}", address_format),
    };
    
    // Check each derivation path
    for path in derivation_paths {
        let derived_key = root_key.derive_priv(&secp, &path)
            .expect("Failed to derive private key");
        
        // Generate the address based on the format
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
            _ => panic!("Unsupported address format: {}", address_format),
        };
        
        if address.to_string() == config.expected_address {
            println!("\n===============================");
            println!("🎉 MATCH FOUND WITH EMPTY PASSPHRASE! 🎉");
            println!("===============================");
            println!("🔑 No additional passphrase needed");
            println!("🔍 Address: {}", address);
            println!("🔍 Path: {}", path);
            println!("===============================");
            return Ok(());
        }
    }
    
    println!("Empty passphrase check: No match");
    println!("Searching for passphrase...");

    // Get list of wordlist files
    println!("Resolved wordlist path: {}", &config.wordlist_path);
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
    
    // Check for changed files
    let mut changed_files = false;
    for file_path in &wordlist_files {
        if state.has_file_changed(file_path)? {
            println!("File {} has changed since last run", file_path.display());
            changed_files = true;
        }
    }
    
    // Reset changed files in state
    if changed_files {
        println!("Some files have changed, updating state");
        state.reset_changed_files(&wordlist_files)?;
    }
    
    // Get unprocessed files
    let files_to_process = state.get_unprocessed_files(&wordlist_files);
    println!("Processing {} out of {} wordlist files", files_to_process.len(), wordlist_files.len());
    
    // Create a multi-progress bar for tracking all files
    let multi_progress = MultiProgress::new();
    
    // Flag to check if passphrase is found
    let passphrase_found = Arc::new(AtomicBool::new(false));
    
    // Process each unprocessed wordlist file
    for (index, file_path) in files_to_process.iter().enumerate() {
        if passphrase_found.load(Ordering::Relaxed) {
            break;
        }
        
        println!("Processing file {}/{}: {}", index + 1, files_to_process.len(), file_path.display());
        
        process_wordlist_file(
            &file_path,
            config,
            &passphrase_found,
            address_format,
            &multi_progress,
            &mut state,
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