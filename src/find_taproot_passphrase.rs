use bitcoin::secp256k1::{Secp256k1, PublicKey};
use bitcoin::util::bip32::{ExtendedPrivKey, DerivationPath};
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::taproot::TaprootBuilder;
use bitcoin::XOnlyPublicKey;
use bip39::{Mnemonic, Language};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use std::sync::Arc;
use std::fs::File;
use std::path::Path;
use log::{warn};
use memmap::Mmap;
use crate::config::Config;
use std::io::{self, ErrorKind};

fn derive_taproot_key(master_key: &ExtendedPrivKey, index: u32) -> Result<XOnlyPublicKey, bitcoin::util::bip32::Error> {
    let secp = Secp256k1::new();
    let path: DerivationPath = format!("m/86'/0'/0'/0/{}", index).parse()?;
    let derived_key = master_key.derive_priv(&secp, &path)?;
    let public_key = PublicKey::from_secret_key(&secp, &derived_key.private_key);
    Ok(XOnlyPublicKey::from(public_key))
}

pub fn find_taproot_passphrase(config: &Arc<Config>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting find_taproot_passphrase function");
    println!("Config wordlist_path: {}", &config.wordlist_path);
    
    // Ensure the wordlist_path is a directory
    let path = Path::new(&config.wordlist_path);
    if !path.exists() {
        return Err(format!("Wordlist directory '{}' does not exist", &config.wordlist_path).into());
    }
    if !path.is_dir() {
        return Err(format!("Wordlist path '{}' is not a directory", &config.wordlist_path).into());
    }
    
    // Get list of wordlist files
    println!("Looking for wordlist files in: {}", &config.wordlist_path);
    let wordlist_files = match rust_btc_passphrase_finder::wordlist::get_wordlist_files(&config.wordlist_path) {
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
    
    // Process the first wordlist file for now
    // In a real implementation, you would process all files
    let file_path = &wordlist_files[0];
    println!("Processing file: {}", file_path.display());
    
    // Open and memory-map the wordlist file
    let file = File::open(file_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let lines: Vec<&str> = mmap.split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| std::str::from_utf8(line).map_err(|_| io::Error::new(ErrorKind::InvalidData, "Invalid UTF-8")))
        .collect::<Result<Vec<&str>, io::Error>>()?;

    // Create a progress bar
    let pb = ProgressBar::new(lines.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .progress_chars("#>-"));

    // Create a custom thread pool
    let pool = ThreadPoolBuilder::new().num_threads(config.num_threads).build()?;

    // Flag to check if passphrase is found
    let passphrase_found = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Perform parallel processing within the custom thread pool
    pool.install(|| {
        lines.par_iter().for_each(|&passphrase| {
            let mnemonic = Mnemonic::parse_in(Language::English, &config.seed_phrase).expect("Failed to create mnemonic");
            let seed = mnemonic.to_seed(passphrase);
            let secp = Secp256k1::new();
            let root_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).expect("Failed to create root key");

            for i in 0..config.address_paths_to_search {
                let xonly_pubkey = derive_taproot_key(&root_key, i as u32).expect("Failed to derive taproot key");
                let taproot_output_key = TaprootBuilder::new()
                    .finalize(&secp, xonly_pubkey)
                    .expect("Failed to finalize taproot builder");
                let taproot_address = Address::p2tr_tweaked(taproot_output_key.output_key(), Network::Bitcoin);

                if taproot_address.to_string() == config.expected_address {
                    println!("\n===============================");
                    println!("🎉 HURRA! Passphrase found! 🎉");
                    println!("===============================");
                    println!(" Passphrase: {}", passphrase);
                    println!("📬 Address format: taproot");
                    println!("===============================");
                    println!("✨ If you found my program helpful, I would greatly appreciate a donation via Bitcoin Lightning!");
                    println!("⚡ Lightning address: aldobarazutti@getalby.com");
                    println!("🙏 Thank you very much!");
                    println!("📬 If you want to contact me, you can find me on Nostr!");
                    println!("🔗 npub: npub1hht9umpeet75w55uzs9lq6ksayfpcvl9lk64hye75j0yj4husq5ss8xsry");
                    println!("===============================");
                    passphrase_found.store(true, std::sync::atomic::Ordering::SeqCst);
                    std::process::exit(0);
                }
            }

            pb.inc(1);
        });
    });

    pb.finish_with_message("Done");

    // Check if passphrase was found
    if !passphrase_found.load(std::sync::atomic::Ordering::SeqCst) {
        warn!("Passphrase not found.");
        println!("\n===============================");
        println!("⚠️ Oops! Passphrase not found ⚠️");
        println!("===============================");
        println!("📬 Address format: taproot");
        println!("===============================");
    }

    Ok(())
}