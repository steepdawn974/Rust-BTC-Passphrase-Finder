use bitcoin::secp256k1::Secp256k1;
use bip39::{Mnemonic, Language};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use memmap::Mmap;
use std::sync::Arc;
use log::warn;
use std::fs::File;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::network::constants::Network;
use crate::config::Config;
use rust_btc_passphrase_finder::wordlist;
use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
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

    println!("Processing {} wordlist files", wordlist_files.len());

    // Create a simple progress bar for overall progress
    let overall_pb = ProgressBar::new(wordlist_files.len() as u64);
    overall_pb.set_style(ProgressStyle::default_bar()
        .template("[{bar:40.green/white}] {pos}/{len} files processed ({eta})")
        .progress_chars("█=>-"));
    
    // Create a dummy multi-progress bar for compatibility with the function signature
    let multi_progress = MultiProgress::new();

    // Flag to check if passphrase is found
    let passphrase_found = Arc::new(AtomicBool::new(false));

    // Process each wordlist file
    for (index, file_path) in wordlist_files.iter().enumerate() {
        if passphrase_found.load(Ordering::Relaxed) {
            break;
        }
        
        println!("\nProcessing file {}/{}: {}", index + 1, wordlist_files.len(), file_path.display());
        overall_pb.set_position(index as u64);
        overall_pb.set_message(format!("File {}/{}", index + 1, wordlist_files.len()));

        process_wordlist_by_fingerprint(
            &file_path,
            config,
            &passphrase_found,
            &multi_progress,
        )?;
    }
    
    overall_pb.finish_with_message("All files processed");

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
) -> io::Result<()> {
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    let metadata = match file.metadata() {
        Ok(m) => m,
        Err(e) => return Err(e),
    };

    if metadata.len() == 0 {
        return Ok(());
    }
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
                    println!("📬 If you want to contact me, you can find me on Nostr!");
                    println!("🔗 npub: npub1hht9umpeet75w55uzs9lq6ksayfpcvl9lk64hye75j0yj4husq5ss8xsry");
                    println!("===============================");
                    passphrase_found.store(true, Ordering::SeqCst);
                    std::process::exit(0);
                }
            }
            
            pb.inc(1);
        });
    });

    pb.finish();
    Ok(())
}
