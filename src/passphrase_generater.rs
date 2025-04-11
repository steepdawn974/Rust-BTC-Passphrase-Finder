use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use crate::config::Config;
use crate::regex_parser::{RegexExpander, RegexError};

/// Maximum number of combinations allowed for regex pattern expansion
const MAX_COMBINATIONS: usize = 2_000_000; // Increased limit to handle patterns like [0-9]{4,6}
/// Maximum size of each wordlist file in bytes
const MAX_FILE_SIZE: usize = 1_000_000; // 1MB per file
/// Estimated average bytes per word (including newline)
const AVG_BYTES_PER_WORD: usize = 8;

/// Generates a list of words based on the given regex pattern
/// 
/// # Arguments
/// * `pattern` - A regex pattern string that defines the format of words to generate
/// 
/// # Returns
/// * `Result<Vec<String>, RegexError>` - A vector of generated words or an error
fn generate_words(pattern: &str) -> Result<Vec<String>, RegexError> {
    let expander = RegexExpander::new(MAX_COMBINATIONS);
    expander.expand_pattern(pattern)
}

/// Saves a chunk of words to a numbered wordlist file
/// 
/// # Arguments
/// * `words` - Slice of words to save
/// * `dir_path` - Base directory path for wordlist files
/// * `file_number` - Number to append to the filename
/// 
/// # Returns
/// * `io::Result<()>` - Success or IO error
fn save_words_chunk(words: &[String], dir_path: &str, file_number: usize) -> io::Result<()> {
    fs::create_dir_all(dir_path)?;
    
    let file_path = PathBuf::from(dir_path)
        .join(format!("wordlist_{:04}.txt", file_number));
    
    let mut file = File::create(&file_path)?;
    for word in words {
        writeln!(file, "{}", word)?;
    }
    
    println!("Created wordlist file: {}", file_path.display());
    Ok(())
}

/// Generates passphrases based on the regex pattern and saves them to multiple files
/// 
/// # Arguments
/// * `config` - Reference to the Config struct containing application settings
/// 
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error
/// Removes all existing wordlist files from the target directory
/// 
/// # Arguments
/// * `dir_path` - Path to the directory containing wordlist files
/// 
/// # Returns
/// * `io::Result<()>` - Success or IO error
fn cleanup_existing_wordlists(dir_path: &str) -> io::Result<()> {
    // Create directory if it doesn't exist
    fs::create_dir_all(dir_path)?;
    
    // Read directory entries
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        
        // Check if the file is a wordlist file
        if path.is_file() && 
           path.file_name()
               .and_then(|n| n.to_str())
               .map(|n| n.starts_with("wordlist_") && n.ends_with(".txt"))
               .unwrap_or(false) {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

pub fn generate_and_save_passphrases(config: &Arc<Config>) -> Result<(), Box<dyn std::error::Error>> {
    // Clean up existing wordlist files
    println!("Cleaning up existing wordlist files...");
    cleanup_existing_wordlists(&config.wordlist_path)?;
    
    println!("Generating passphrases using regex pattern: {}", config.passphrase);
    let words = generate_words(&config.passphrase)?;
    println!("Generated {} possible passphrases", words.len());
    
    // Calculate words per file based on MAX_FILE_SIZE
    let words_per_file = MAX_FILE_SIZE / AVG_BYTES_PER_WORD;
    let total_files = (words.len() + words_per_file - 1) / words_per_file;
    
    println!("Splitting into approximately {} files", total_files);
    
    // Split words into chunks and save each chunk
    for (i, chunk) in words.chunks(words_per_file).enumerate() {
        save_words_chunk(chunk, &config.wordlist_path, i + 1)?;
    }
    
    println!("Successfully wrote {} wordlist files to: {}", total_files, config.wordlist_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs::read_to_string;

    #[test]
    fn test_generate_words() {
        let result = generate_words("[0-9]{2}").unwrap();
        assert_eq!(result.len(), 100);
        assert!(result.contains(&"00".to_string()));
        assert!(result.contains(&"99".to_string()));
    }

    #[test]
    fn test_save_words_chunk() {
        let temp_dir = tempdir().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap();
        let words = vec!["test1".to_string(), "test2".to_string()];

        save_words_chunk(&words, dir_path, 1).unwrap();

        let file_path = PathBuf::from(dir_path).join("wordlist_0001.txt");
        let content = read_to_string(file_path).unwrap();
        assert_eq!(content, "test1\ntest2\n");
    }

    #[test]
    fn test_generate_and_save_passphrases() {
        let temp_dir = tempdir().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap().to_string();

        let config = Arc::new(Config {
            seed_phrase: "test seed".to_string(),
            expected_address: "test address".to_string(),
            wordlist_path: dir_path.clone(),
            num_threads: 1,
            passphrase: "[0-9]{2}".to_string(),
            address_paths_to_search: 1,
        });

        generate_and_save_passphrases(&config).unwrap();

        // Check if files were created
        let entries: Vec<_> = fs::read_dir(&dir_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();

        assert!(!entries.is_empty());
        assert!(entries.iter().all(|name| name.starts_with("wordlist_") && name.ends_with(".txt")));
    }

    #[test]
    fn test_cleanup_existing_wordlists() {
        let temp_dir = tempdir().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap();

        // Create some test files
        let test_files = vec![
            "wordlist_0001.txt",
            "wordlist_0002.txt",
            "other_file.txt", // This file should not be deleted
        ];

        for file in &test_files {
            let path = PathBuf::from(dir_path).join(file);
            File::create(&path).unwrap();
        }

        // Run cleanup
        cleanup_existing_wordlists(dir_path).unwrap();

        // Check remaining files
        let entries: Vec<_> = fs::read_dir(dir_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();

        // Only other_file.txt should remain
        assert_eq!(entries.len(), 1);
        assert!(entries.contains(&"other_file.txt".to_string()));
    }
}