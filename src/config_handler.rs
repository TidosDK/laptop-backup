use anyhow::{Context, Result};
use std::{fs, path::Path};

pub fn load_paths_from_file(paths_file: impl AsRef<Path>) -> Result<Vec<String>> {
    let paths_file: &Path = paths_file.as_ref();

    let path_file_contents: String = fs::read_to_string(paths_file)
        .with_context(|| format!("could not read paths from {:?}", paths_file))?;

    let mut paths: Vec<String> = Vec::new();

    for path in path_file_contents.lines() {
        paths.push(path.to_string());
    }

    return Ok(paths);
}

pub fn load_public_key_from_file(public_key_file: &str) -> Result<String> {
    let public_key_file: &Path = public_key_file.as_ref();

    let public_key: String = fs::read_to_string(public_key_file)
        .with_context(|| format!("could not read public key from {:?}", public_key_file))?;

    return Ok(public_key);
}
