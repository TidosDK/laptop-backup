mod backup_library;

use crate::backup_library::{
    backup_directory_contents, encrypt_file, load_paths_from_file, load_public_key_from_file,
    zip_files_in_folder,
};

static PATHS_FILE: &str = "paths.txt";
static PUBLIC_KEY_FILE: &str = "public_key.txt";
static BACKUP_FOLDER_PATH: &str = "laptop-backup";

fn main() {
    let paths: Vec<String> = load_paths_from_file(PATHS_FILE).expect("failed to load path file");
    let public_encryption_key: String =
        load_public_key_from_file(PUBLIC_KEY_FILE).expect("failed to load public key");

    for path in paths {
        if let Err(err) = backup_directory_contents(path, BACKUP_FOLDER_PATH) {
            eprintln!("Error retrieving file/folder: {:?}", err);
        }
    }

    let archive_file: std::path::PathBuf = zip_files_in_folder(BACKUP_FOLDER_PATH).unwrap(); // TODO: handle error

    if let Err(err) = encrypt_file(archive_file, public_encryption_key) {
        eprintln!("Encryption failed: {err}");
        std::process::exit(1);
    }
}
