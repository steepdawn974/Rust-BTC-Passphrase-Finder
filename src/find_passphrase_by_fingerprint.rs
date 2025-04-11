use bitcoin::secp256k1::Secp256k1;
use bip39::{Mnemonic, Language};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use memmap::Mmap;
use std::sync::Arc;
use std::fs::File;
use std::path::Path;
use log::{warn, info};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::network::constants::Network;
use crate::config::Config;
use crate::state::{State, ProcessingStatus};
use rust_btc_passphrase_finder::wordlist;
use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};

// Static variable to store the found passphrase
static mut FOUND_PASSPHRASE: Option<String> = None;
use num_cpus;

/// Find a passphrase that generates the target master fingerprint
/// 
/// This function searches through multiple wordlist files in parallel, looking for
/// a passphrase that generates the target master fingerprint.
/// 
/// # Arguments
/// * `config` - Configuration containing search parameters and paths
/// 
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error
pub fn find_passphrase_by_fingerprint(config: &Arc<Config>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting find_passphrase function (by master fingerprint)");
    println!("Expected master fingerprint: {}", &config.expected_masterfingerprint);
    
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
            let mut state = match State::load_or_create(&config.expected_masterfingerprint) {
                Ok(state) => state,
                Err(e) => {
                    warn!("Failed to load state: {}", e);
                    State::new(&config.expected_masterfingerprint)
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
            println!("🔍 Master fingerprint: {}", &config.expected_masterfingerprint);
            println!("===============================");
            
            return Ok(());
        }
    }
    
    // First check if the seed phrase without any passphrase matches the expected fingerprint
    let mnemonic = Mnemonic::parse_in(Language::English, &config.seed_phrase)
        .expect("Failed to create mnemonic");
    let seed = mnemonic.to_seed(""); // Empty passphrase
    let secp = Secp256k1::new();
    let root_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed)
        .expect("Failed to create root key");
    let fingerprint = root_key.fingerprint(&secp);
    let fingerprint_hex = format!("{:08x}", fingerprint);
    
    if fingerprint_hex == config.expected_masterfingerprint.to_lowercase() {
        println!("\n===============================");
        println!("🎉 MATCH FOUND WITH EMPTY PASSPHRASE! 🎉");
        println!("===============================");
        println!("🔑 No additional passphrase needed");
        println!("🔍 Master fingerprint: {}", fingerprint_hex);
        println!("===============================");
        return Ok(());
    } else {
        println!("Empty passphrase check: No match (fingerprint: {})", fingerprint_hex);
        println!("Searching for passphrase...");
    }
    
    // Initialize or load state
    let mut state = match State::load_or_create(&config.expected_masterfingerprint) {
        Ok(state) => {
            println!("Loaded existing state file");
            state
        },
        Err(e) => {
            warn!("Failed to load state: {}", e);
            println!("Creating new state file");
            State::new(&config.expected_masterfingerprint)
        }
    };
    
    // Get list of wordlist files
    let wordlist_files = match wordlist::get_wordlist_files(&config.wordlist_path) {
        Ok(files) => files,
        Err(e) => {
            println!("Error getting wordlist files: {}", e);
            return Err(e.into());
        }
    };
    if wordlist_files.is_empty() {
        return Err("No wordlist files found. Run 'Generate Passphrases' first.".into());
    }

    // Check if any files have changed since last run
    let mut files_changed = false;
    for file_path in &wordlist_files {
        if let Ok(true) = state.has_file_changed(file_path) {
            files_changed = true;
            println!("File {} has changed since last run", file_path.display());
        }
    }
    
    // If files have changed, reset state for those files
    if files_changed {
        println!("Some files have changed, updating state");
        if let Err(e) = state.reset_changed_files(&wordlist_files) {
            warn!("Failed to reset changed files: {}", e);
        }
    }
    
    // Get unprocessed files
    let unprocessed_files = state.get_unprocessed_files(&wordlist_files);
    
    if unprocessed_files.is_empty() {
        println!("All files have been processed, no match found");
        return Ok(());
    }
    
    println!("Processing {} out of {} wordlist files", unprocessed_files.len(), wordlist_files.len());

    // Create a multi-progress bar for tracking all files
    let multi_progress = MultiProgress::new();

    // Flag to check if passphrase is found
    let passphrase_found = Arc::new(AtomicBool::new(false));

    // Process each unprocessed wordlist file
    for (i, file_path) in unprocessed_files.iter().enumerate() {
        if passphrase_found.load(Ordering::Relaxed) {
            break;
        }
        
        println!("Processing file {}/{}: {}", i + 1, unprocessed_files.len(), file_path.display());

        process_wordlist_by_fingerprint(
            &file_path,
            config,
            &passphrase_found,
            &multi_progress,
            &mut state,
        )?;
    }
    
    println!("All files processed");

    // Check if passphrase was found
    if !passphrase_found.load(Ordering::SeqCst) {
        warn!("Passphrase not found in any wordlist file.");
        println!("\n===============================");
        println!("⚠️ Oops! Passphrase not found ⚠️");
        println!("===============================");
        println!("🔍 Expected master fingerprint: {}", &config.expected_masterfingerprint);
        println!("===============================");
    }

    Ok(())
}

/// Process a single wordlist file to find the matching passphrase by master fingerprint
/// 
/// # Arguments
/// * `file_path` - Path to the wordlist file
/// * `config` - Reference to the configuration
/// * `passphrase_found` - Atomic flag indicating if passphrase was found
/// * `multi_progress` - Multi-progress bar for tracking progress
/// 
/// # Returns
/// * `io::Result<()>` - Success or IO error
fn process_wordlist_by_fingerprint(
    file_path: &std::path::Path,
    config: &Arc<Config>,
    passphrase_found: &Arc<AtomicBool>,
    _multi_progress: &MultiProgress, // Unused parameter kept for API compatibility
    state: &mut State,
) -> io::Result<()> {
    info!("Processing file: {}", file_path.display());
    
    // Check if the file has already been processed and hasn't changed
    let path_str = file_path.to_string_lossy().to_string();
    if let Some(file_info) = state.wordlist_files.get(&path_str) {
        if file_info.status == ProcessingStatus::Processed {
            // Verify the hash to make sure the file hasn't changed
            if !state.has_file_changed(file_path)? {
                println!("File {} already processed, skipping", file_path.display());
                return Ok(());
            } else {
                println!("File {} has changed since last processing, re-processing", file_path.display());
            }
        } else if file_info.status == ProcessingStatus::MatchFound {
            // A match was previously found in this file
            println!("A match was previously found in file {}, re-processing to verify", file_path.display());
        }
    }
    
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
        // Update state for empty file
        state.update_file_info(file_path, ProcessingStatus::Processed)?;
        state.save(&State::get_state_file_path())?;
        return Ok(());
    };
    let mmap = match unsafe { Mmap::map(&file) } {
        Ok(m) => m,
        Err(e) => return Err(e),
    };
    let lines: Vec<&str> = mmap.split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| std::str::from_utf8(line).map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid UTF-8")))
        .collect::<Result<Vec<&str>, io::Error>>()?;
    
    // Create a standalone progress bar for this file
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
    let pb = ProgressBar::new(lines.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template(&format!("[{{bar:50.cyan/blue}}] {}: {{pos}}/{{len}} ({{eta}})", file_name))
        .progress_chars("█=>-"));
    pb.enable_steady_tick(100);

    // Create a custom thread pool with optimal thread count
    let num_threads = std::cmp::max(config.num_threads, num_cpus::get());
    let pool = ThreadPoolBuilder::new().num_threads(num_threads).build()
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    // Pre-create the expected fingerprint for comparison
    let expected_fingerprint = config.expected_masterfingerprint.to_lowercase();
    
    // No need to clone the file path as we're not using it in the closure
    
    // Perform parallel processing within the custom thread pool
    pool.install(|| {
        lines.par_iter().for_each(|&passphrase| {
            if !passphrase_found.load(Ordering::Relaxed) {
                // Create these per thread but not per passphrase
                let mnemonic = Mnemonic::parse_in(Language::English, &config.seed_phrase)
                    .expect("Failed to create mnemonic");
                let secp = Secp256k1::new();
                
                let seed = mnemonic.to_seed(passphrase);
                let root_key = match ExtendedPrivKey::new_master(Network::Bitcoin, &seed) {
                    Ok(key) => key,
                    Err(_) => return,
                };
                
                // Get master fingerprint (4 bytes) and convert to hex string
                let fingerprint = root_key.fingerprint(&secp);
                let fingerprint_hex = format!("{:08x}", fingerprint);
                
                if fingerprint_hex == expected_fingerprint {
                    // Clear progress bar before printing the success message
                    pb.finish_and_clear();
                    
                    println!("\n===============================");
                    println!("🎉 HURRA! Passphrase found! 🎉");
                    println!("===============================");
                    println!("🔑 Passphrase: {}", passphrase);
                    println!("🔍 Master fingerprint: {}", fingerprint_hex);
                    println!("===============================");
                    println!("✨ If you found my program helpful, I would greatly appreciate a donation via Bitcoin Lightning!");
                    println!("⚡ Lightning address: aldobarazutti@getalby.com");
                    println!("🙏 Thank you very much!");
                    println!("📮 If you want to contact me, you can find me on Nostr!");
                    println!("🔗 npub: npub1hht9umpeet75w55uzs9lq6ksayfpcvl9lk64hye75j0yj4husq5ss8xsry");
                    println!("===============================");
                    
                    // We need to update the state before exiting
                    // Instead of just writing to a temporary file, we'll update the state directly
                    passphrase_found.store(true, Ordering::SeqCst);
                    
                    // Store the found passphrase in a static variable so we can access it later
                    unsafe {
                        FOUND_PASSPHRASE = Some(passphrase.to_string());
                    }
                    
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
                    
                    // Clone the expected_fingerprint before moving it into the closure
                    let expected_fingerprint_clone = expected_fingerprint.clone();
                    
                    // Update the state in a separate thread to avoid deadlocks
                    std::thread::spawn(move || {
                        // Load the current state
                        if let Ok(mut state) = State::load_or_create(&expected_fingerprint_clone) {
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
