use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use log::{info, warn};

/// Status of a wordlist file processing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProcessingStatus {
    /// File has been processed and no match was found
    Processed,
    /// File has been processed and a match was found
    MatchFound,
    /// File has not been processed yet
    NotProcessed,
}

/// Information about a processed wordlist file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistFileInfo {
    /// Path to the wordlist file
    pub path: String,
    /// SHA-256 hash of the file content
    pub hash: String,
    /// Timestamp when the file was last processed (Unix timestamp)
    pub last_processed: u64,
    /// Status of the file processing
    pub status: ProcessingStatus,
}

/// State of the passphrase finder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// Information about processed wordlist files
    pub wordlist_files: HashMap<String, WordlistFileInfo>,
    /// Timestamp when the state was last updated
    pub last_updated: u64,
    /// Target fingerprint or address being searched
    pub target: String,
    /// The found passphrase, if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_passphrase: Option<String>,
}

impl State {
    /// Create a new state
    pub fn new(target: &str) -> Self {
        Self {
            wordlist_files: HashMap::new(),
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            target: target.to_string(),
            found_passphrase: None,
        }
    }

    /// Load state from a file
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let state: State = serde_json::from_str(&contents)?;
        Ok(state)
    }

    /// Save state to a file
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(contents.as_bytes())?;
        Ok(())
    }

    /// Update the state with information about a wordlist file
    pub fn update_file_info(
        &mut self,
        file_path: &Path,
        status: ProcessingStatus,
    ) -> io::Result<()> {
        let path_str = file_path.to_string_lossy().to_string();
        let hash = Self::calculate_file_hash(file_path)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        self.wordlist_files.insert(
            path_str.clone(),
            WordlistFileInfo {
                path: path_str,
                hash,
                last_processed: now,
                status,
            },
        );

        self.last_updated = now;
        Ok(())
    }

    /// Calculate SHA-256 hash of a file
    fn calculate_file_hash(file_path: &Path) -> io::Result<String> {
        // Get file metadata for size and modification time
        let metadata = std::fs::metadata(file_path)?;
        let size = metadata.len();
        let modified = metadata.modified()?;
        
        // Convert modified time to seconds since epoch
        let modified_secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        
        // Use file size and modification time as part of the hash
        // This is faster than reading the entire file and still reliable for change detection
        let hash_input = format!("{}-{}", size, modified_secs);
        
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let result = hasher.finalize();
        
        Ok(format!("{:x}", result))
    }

    /// Check if a file has changed since it was last processed
    pub fn has_file_changed(&self, file_path: &Path) -> io::Result<bool> {
        let path_str = file_path.to_string_lossy().to_string();
        
        if let Some(info) = self.wordlist_files.get(&path_str) {
            let current_hash = Self::calculate_file_hash(file_path)?;
            Ok(info.hash != current_hash)
        } else {
            // File not in state, so it has "changed" (never processed)
            Ok(true)
        }
    }

    /// Get all unprocessed files
    pub fn get_unprocessed_files(&self, wordlist_files: &[PathBuf]) -> Vec<PathBuf> {
        let mut unprocessed = Vec::new();
        
        for file_path in wordlist_files {
            let path_str = file_path.to_string_lossy().to_string();
            
            match self.wordlist_files.get(&path_str) {
                Some(info) if info.status == ProcessingStatus::Processed => {
                    // Skip processed files
                    continue;
                }
                Some(info) if info.status == ProcessingStatus::MatchFound => {
                    // Skip files where a match was found
                    continue;
                }
                _ => {
                    // File is unprocessed or not in state
                    unprocessed.push(file_path.clone());
                }
            }
        }
        
        unprocessed
    }

    /// Reset state for files that have changed
    pub fn reset_changed_files(&mut self, wordlist_files: &[PathBuf]) -> io::Result<()> {
        for file_path in wordlist_files {
            if self.has_file_changed(file_path)? {
                let path_str = file_path.to_string_lossy().to_string();
                
                if let Some(info) = self.wordlist_files.get_mut(&path_str) {
                    info.status = ProcessingStatus::NotProcessed;
                    info.hash = Self::calculate_file_hash(file_path)?;
                    info.last_processed = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs();
                }
            }
        }
        
        Ok(())
    }
    
    /// Update the found passphrase
    pub fn update_found_passphrase(&mut self, passphrase: &str) {
        self.found_passphrase = Some(passphrase.to_string());
        self.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
    }

    /// Get the state file path
    pub fn get_state_file_path() -> PathBuf {
        PathBuf::from("state.json")
    }

    /// Load or create state
    pub fn load_or_create(target: &str) -> io::Result<Self> {
        let path = Self::get_state_file_path();
        
        if path.exists() {
            match Self::load(&path) {
                Ok(state) => {
                    // If the target has changed, create a new state
                    if state.target != target {
                        info!("Target has changed, creating new state");
                        let new_state = Self::new(target);
                        new_state.save(&path)?;
                        Ok(new_state)
                    } else {
                        Ok(state)
                    }
                }
                Err(e) => {
                    warn!("Failed to load state: {}", e);
                    let new_state = Self::new(target);
                    new_state.save(&path)?;
                    Ok(new_state)
                }
            }
        } else {
            let new_state = Self::new(target);
            new_state.save(&path)?;
            Ok(new_state)
        }
    }
}
