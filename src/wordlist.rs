use std::fs;
use std::path::PathBuf;

/// Get all wordlist files in the specified directory
/// 
/// # Arguments
/// * `dir_path` - Path to the directory containing wordlist files
/// 
/// # Returns
/// * `io::Result<Vec<PathBuf>>` - List of paths to wordlist files, sorted by name
pub fn get_wordlist_files(dir_path: &str) -> std::io::Result<Vec<PathBuf>> {
    let resolved_path = std::fs::canonicalize(dir_path)?;
    println!("Resolved wordlist path: {}", resolved_path.display());

    println!("get_wordlist_files: Looking in directory: {}", dir_path);
    let mut wordlist_files = Vec::new();
    
    // Read directory entries
    println!("get_wordlist_files: Attempting to read directory");
    let dir_entries = match fs::read_dir(&resolved_path) {
        Ok(entries) => entries,
        Err(e) => {
            println!("get_wordlist_files: Error reading directory: {}", e);
            return Err(e);
        }
    };
    
    for entry in dir_entries {
        let entry = entry?;
        let path = entry.path();
        
        // Check if the file is a wordlist file
        if path.is_file() && 
           path.file_name()
               .and_then(|n| n.to_str())
               .map(|n| n.starts_with("wordlist_") && n.ends_with(".txt"))
               .unwrap_or(false) {
            wordlist_files.push(path);
        }
    }
    
    // Sort files by name to ensure consistent processing order
    wordlist_files.sort();
    Ok(wordlist_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn test_get_wordlist_files() {
        let temp_dir = tempdir().unwrap();
        let dir_path = temp_dir.path().to_str().unwrap();

        // Create some test files
        let test_files = vec![
            "wordlist_0002.txt",
            "wordlist_0001.txt",
            "other_file.txt",
        ];

        for file in &test_files {
            let path = PathBuf::from(dir_path).join(file);
            File::create(&path).unwrap();
        }

        // Get wordlist files
        let files = get_wordlist_files(dir_path).unwrap();
        
        // Should return 2 files in sorted order
        assert_eq!(files.len(), 2);
        assert!(files[0].to_str().unwrap().ends_with("wordlist_0001.txt"));
        assert!(files[1].to_str().unwrap().ends_with("wordlist_0002.txt"));
    }
}
