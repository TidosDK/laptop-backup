mod backup_library;

use crate::backup_library::{
    backup_files_from_folder, encrypt_file, load_paths, load_public_key, zip_files_in_folder,
};

static PATHS_FILE: &str = "paths.txt";
static PUBLIC_KEY_FILE: &str = "public_key.txt";

fn main() {
    let paths: Vec<String> = load_paths(PATHS_FILE).expect("failed to load path file");
    let public_encryption_key: String =
        load_public_key(PUBLIC_KEY_FILE).expect("failed to load public key");

    for path in paths {
        if let Err(err) = backup_files_from_folder(path) {
            eprintln!("Error retrieving file/folder: {:?}", err);
        }
    }

    let archive_file: std::path::PathBuf = zip_files_in_folder().unwrap(); // TODO: handle error

    if let Err(err) = encrypt_file(archive_file, public_encryption_key) {
        eprintln!("Encryption failed: {err}");
        std::process::exit(1);
    }
}
