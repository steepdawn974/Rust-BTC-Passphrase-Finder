## Overview
This program is a Bitcoin Passphrase Finder that processes a list of possible passphrases to find the one that matches a specific Bitcoin address or master fingerprint. It uses parallel processing to efficiently check passphrases.

## Problem Statement
Bitcoin addresses are often generated through a combination of a seed phrase and a passphrase. This passphrase serves as an additional security layer to protect access to the Bitcoin wallet. However, if the passphrase is lost or forgotten, access to the wallet and the bitcoins contained within it may become impossible.

This program solves the problem of finding a lost or forgotten passphrase by going through a list of possible passphrases and checking if they match a specific Bitcoin address or master fingerprint. This is particularly useful for users who have forgotten their passphrase but still know the seed phrase and the expected Bitcoin address or master fingerprint.


## Video Demonstration
https://old.bitchute.com/video/849qfl1yiVqf/


## How It Works
1. **Configuration**: The program reads a configuration file (`config.toml`) that contains the seed phrase, the expected Bitcoin address or master fingerprint, the path to the wordlist, and the number of threads for parallel processing.
2. **State Management**: The program uses a state management system to track the progress of wordlist file processing, allowing it to resume the search after an interruption without having to reprocess already processed files.
3. **Reading the Wordlist**: The wordlist is opened and memory-mapped. Each line of the file is converted into a vector of strings.
4. **Progress Bar**: A progress bar is created to display the progress of the brute-force process.
5. **Parallel Processing**: The wordlist is processed in parallel. For each passphrase, a mnemonic object is created and a seed is generated from it. A private key is derived from this seed, and a Bitcoin address or master fingerprint is generated from this key.
6. **Verification**: If the generated address or fingerprint matches the expected one, the passphrase is logged, saved to the state file, and the program exits. The progress bar is updated with each iteration and completed with a message at the end.

## Supported Address Formats
The program supports the following five Bitcoin address formats:
1. **Legacy (P2PKH)**: Addresses that start with `1`.
2. **Pay-to-Script-Hash (P2SH)**: Addresses that start with `3`.
3. **Native SegWit (P2WPKH)**: Addresses that start with `bc1q` and are 42 characters long.
4. **Pay-to-Witness-Script-Hash (P2WSH)**: Addresses that start with `bc1q` and are longer than 42 characters.
5. **Taproot (P2TR)**: Addresses that start with `bc1p`.

## Configuration Options
The configuration file `config.toml` contains the following options:
- `seed_phrase`: The seed phrase used to generate the passphrase.
- `expected_address`: The expected Bitcoin address that should match the generated passphrase.
- `expected_masterfingerprint`: The expected master fingerprint that should match the generated passphrase.
- `wordlist_path`: The path to the file with the wordlist.
- `num_threads`: The number of threads to use for parallel processing.
- `passphrase`: A regex pattern for generating passphrases. Examples:
  - `[A-Z][0-9]{2}` - An uppercase letter followed by two digits
  - `Q[a-z]{3}[0-9]` - The letter Q followed by three lowercase letters and a digit
  - `[A-Z]us[A-Z]t[0-9]mz[A-Z]{2}[0-9]{2}QQ` - Complex pattern
- `address_paths_to_search`: The number of address paths to search (1, 2, or 3).

## Running Tests
The project contains unit tests for regex pattern processing and other components. To run the tests:

```bash
# Run all tests
cargo test

# Tests with detailed output
cargo test -- --nocapture

# Run specific tests (e.g. only regex_parser tests)
cargo test regex_parser
```

## Requirements
- Linux
- Rust environment (version 1.70 or higher)
- Cargo (Rust package manager)

## Installation and Usage

### Installation

```bash
# Clone repository
git clone https://github.com/Walpurga03/Rust-BTC-Passphrase-Finder.git
cd Rust-BTC-Passphrase-Finder

# Build project
cargo build --release

# Run
./target/release/rust_btc_passphrase_finder
```

### Configuration

Before using, you need to adjust the configuration file `config.toml`:

```toml
seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
expected_address = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
expected_masterfingerprint = "60008b2f"
wordlist_path = "wordlists"
num_threads = 8
passphrase = "[A-Z][0-9]{2}"
address_paths_to_search = 1
```

### Offline Usage
#### On a PC with Internet Connection
1. **Clone the GitHub repository to a USB stick**:
   ```
   git clone https://github.com/Walpurga03/Rust-BTC-Passphrase-Finder.git /path/to/usb-stick
   cd /path/to/usb-stick/Rust-BTC-Passphrase-Finder
   ```
2. **Install Rustup and Cargo** (if not already installed):
   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```
3. **Build the project and download all dependencies**:
   ```
   cd Rust-BTC-Passphrase-Finder
   cargo build --release
   ```
4. **Copy the Rust toolchain to the USB stick**:
   ```
   cp -r $HOME/.rustup /path/to/usb-stick/Rust-BTC-Passphrase-Finder/rustup
   cp -r $HOME/.cargo /path/to/usb-stick/Rust-BTC-Passphrase-Finder/cargo
   ```

#### On a PC without Internet Connection
1. **Insert the USB stick and navigate to the repository directory**:
   ```
   cd /path/to/usb-stick/Rust-BTC-Passphrase-Finder
   ```
2. **Load environment variables**:
   ```
   source setup_env.sh
   ls -l ./target/release/rust_btc_passphrase_finder
   chmod +x ./target/release/rust_btc_passphrase_finder
   ```
3. **Run the program**:
   ```
   ./target/release/rust_btc_passphrase_finder
   ```


## Notes
- Make sure the wordlist is in UTF-8 format.
- Parallel processing can heavily utilize the CPU. Adjust the number of threads as needed.

## State Management
The program uses a state management system that tracks the progress of wordlist file processing. This allows resuming the search after an interruption without having to reprocess already processed files.

### How It Works
1. **State File**: The program creates a `state.json` file in the project directory that contains information about processed files and found passphrases.
2. **File Hashing**: Each wordlist file is identified by its size and modification time to determine if it has been changed since the last processing.
3. **Processing Status**: For each file, one of the following statuses is stored:
   - `Processed`: The file has been processed, but no match was found.
   - `MatchFound`: A match was found in the file.
   - `NotProcessed`: The file has not been processed yet.

### Benefits
- **Time Saving**: Already processed files are skipped, which can save significant time with large wordlists.
- **Interruption Tolerance**: The search can be interrupted at any time and resumed later.
- **Change Detection**: If a file has been changed, it will automatically be reprocessed.

### Usage
The state management works automatically in the background. When you start the search for a passphrase, the program checks if a state already exists for the current target address or fingerprint and continues processing accordingly. When a passphrase is found, it is stored in the state file along with information about which file contained the match.

## Testing the Program
To test the program, you can generate three addresses for each of the five address types (Legacy, P2SH, SegWit, P2WSH, Taproot) with random seed phrases and passphrases. You can then add these addresses and passphrases to the wordlist and configuration file to test the program.

## Passphrase Generator
The program also includes a passphrase generator that can create a wordlist with existing letters, uppercase and lowercase letters, numbers, and special characters. This feature can be selected from the menu.

## Menu Options
1. **Generate Addresses**: Generates Bitcoin addresses based on the seed phrase and derivation paths.
2. **Find Passphrase (by address)**: Searches the wordlist for the passphrase that matches the expected Bitcoin address.
3. **Find Passphrase (by master fingerprint)**: Searches the wordlist for the passphrase that matches the expected master fingerprint.
4. **Generate Passphrases**: Generates a wordlist with passphrases based on the specified characters and placeholders.