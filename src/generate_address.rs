use bip39::Mnemonic;
use rand::Rng;
use rand::rngs::OsRng;
use std::str::FromStr;
use std::error::Error;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ExtendedPrivKey, DerivationPath};
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::taproot::TaprootBuilder;
use bitcoin::XOnlyPublicKey;
use bitcoin::Script;

/// Derives the Taproot key using the given master key.
fn derive_taproot_key(master_key: &ExtendedPrivKey, index: u32) -> Result<bitcoin::secp256k1::PublicKey, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let path = DerivationPath::from_str(&format!("m/86'/0'/0'/0/{}", index))?;
    let derived_key = master_key.derive_priv(&secp, &path)?;
    Ok(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key.private_key))
}

/// Generates all types of Bitcoin addresses and prints them.
pub fn generate_all_addresses() -> Result<(), Box<dyn std::error::Error>> {

    // Generate a random seed phrase
    let mut entropy = [0u8; 16]; // 128 bits of entropy for 12 words
    OsRng.fill(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    let seed_phrase = mnemonic.to_string();
    println!("Generated seed phrase: {}", seed_phrase);

    // Generate a random passphrase
    let passphrase: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    println!("Generated passphrase: {}", passphrase);

    // Generate the seed from the seed phrase and passphrase
    let seed = mnemonic.to_seed(&passphrase);

    // Create a new secp256k1 context
    let secp = Secp256k1::new();
    let root_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed)?;

    println!("Extended Private Key: {}", root_key);
    println!("\nGenerated Addresses:");
    println!("====================");

    for i in 0..3 {
        // Taproot address
        let taproot_pubkey = derive_taproot_key(&root_key, i)?;
        let xonly_pubkey = XOnlyPublicKey::from(taproot_pubkey);  // Convert to XOnlyPublicKey
        let taproot_output_key = TaprootBuilder::new()
            .finalize(&secp, xonly_pubkey)?;
        let taproot_address = Address::p2tr_tweaked(taproot_output_key.output_key(), Network::Bitcoin);

        // Legacy address (P2PKH)
        let derivation_path_legacy = DerivationPath::from_str(&format!("m/44'/0'/0'/0/{}", i))?;
        let derived_key_legacy = root_key.derive_priv(&secp, &derivation_path_legacy)?;
        let pubkey_legacy = bitcoin::PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key_legacy.private_key),
        };
        let address_legacy = Address::p2pkh(&pubkey_legacy, Network::Bitcoin);

        // Native SegWit address (P2WPKH)
        let derivation_path_segwit = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", i))?;
        let derived_key_segwit = root_key.derive_priv(&secp, &derivation_path_segwit)?;
        let pubkey_segwit = bitcoin::PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key_segwit.private_key),
        };
        let address_segwit = Address::p2wpkh(&pubkey_segwit, Network::Bitcoin)?;

        // Pay-to-Script-Hash (P2SH)
        let derivation_path_p2sh = DerivationPath::from_str(&format!("m/49'/0'/0'/0/{}", i))?;
        let derived_key_p2sh = root_key.derive_priv(&secp, &derivation_path_p2sh)?;
        let pubkey_p2sh = bitcoin::PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key_p2sh.private_key),
        };
        let address_p2sh = Address::p2shwpkh(&pubkey_p2sh, Network::Bitcoin)?;

        // Pay-to-Witness-Script-Hash (P2WSH)
        let derivation_path_p2wsh = DerivationPath::from_str(&format!("m/48'/0'/0'/2/{}", i))?;
        let derived_key_p2wsh = root_key.derive_priv(&secp, &derivation_path_p2wsh)?;
        let pubkey_p2wsh = bitcoin::PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key_p2wsh.private_key),
        };
        let wpkh = pubkey_p2wsh.wpubkey_hash().ok_or("Failed to create WPubkeyHash")?;
        let script = Script::new_v0_p2wpkh(&wpkh);
        let address_p2wsh = Address::p2wsh(&script, Network::Bitcoin);

        // Print the addresses in a structured format
        println!("Address Path {}:", i + 1);
        println!("{:<15} {}", "Legacy(P2PKH):", address_legacy);
        println!("{:<15} {}", "P2SH:", address_p2sh);
        println!("{:<15} {}", "P2WSH:", address_p2wsh);
        println!("{:<15} {}", "SegWit(P2WPKH):", address_segwit);
        println!("{:<15} {}", "Taproot:", taproot_address);
        println!("--------------------");
    }

    Ok(())
}