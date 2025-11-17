use std::fs::{self, File, remove_dir_all, remove_file};
use std::io::{self, BufReader, BufWriter, Error, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use age::{Encryptor, x25519};
use anyhow::{Context, Result, bail};
use chrono::Local;
use tar::Builder;
use walkdir::WalkDir;

static BACKUP_FOLDER_PATH: &str = "laptop-backup";

pub fn load_paths(paths_file: impl AsRef<Path>) -> Result<Vec<String>> {
    let paths_file: &Path = paths_file.as_ref();

    let path_file_contents: String = fs::read_to_string(paths_file)
        .with_context(|| format!("could not read paths from {:?}", paths_file))?;

    let mut paths: Vec<String> = Vec::new();

    for path in path_file_contents.lines() {
        paths.push(path.to_string());
    }

    return Ok(paths);
}

pub fn load_public_key(public_key_file: &str) -> Result<String> {
    let public_key_file: &Path = public_key_file.as_ref();

    let public_key: String = fs::read_to_string(public_key_file)
        .with_context(|| format!("could not read public key from {:?}", public_key_file))?;

    return Ok(public_key);
}

pub fn backup_files_from_folder<T: AsRef<Path>>(source_path: T) -> Result<()> {
    let source_path: PathBuf = PathBuf::from(source_path.as_ref());
    let backup_folder_path: PathBuf = PathBuf::from(BACKUP_FOLDER_PATH);

    if !source_path.is_absolute() {
        bail!("source path '{}' is not absolute", source_path.display());
    }

    if !source_path.is_dir() {
        bail!("source path '{}' is not a directory", source_path.display());
    }

    let relative_source_path: PathBuf = PathBuf::from(
        source_path
            .strip_prefix(Component::RootDir)
            .unwrap_or(&source_path), // unwrap_or returns the default value if the strip_prefix was not able to remove any RootDir component.
    );

    let full_backup_folder_path: PathBuf = backup_folder_path.join(relative_source_path);

    fs::create_dir_all(&full_backup_folder_path)?;

    for entry in fs::read_dir(&source_path)? {
        let file_path = entry?.path();
        copy_file_from_folder(file_path, &full_backup_folder_path)?;
    }

    return Ok(());
}

fn copy_file_from_folder(file: PathBuf, destination_folder: &PathBuf) -> Result<()> {
    if file.is_dir() {
        return backup_folder(file); // The "file" it is actually a folder in this context.
    }

    // Skip non-regular files (symlinks, etc.)
    if !file.is_file() {
        eprintln!(
            "Skipping non-regular file '{}': not a regular file",
            file.display()
        );
        return Ok(());
    }
    let mut file_destination: PathBuf = destination_folder.to_path_buf();

    if let Some(file_name) = file.file_name() {
        file_destination.push(file_name);
    } else {
        eprintln!("Skipping '{}': path has no final component", file.display());
        return Ok(());
    };

    if let Err(err) = fs::copy(&file, &file_destination) {
        eprintln!(
            "Failed to copy {} → {}: {}",
            file.display(),
            file_destination.display(),
            err
        );
    }

    return Ok(());
}

fn backup_folder(folder: PathBuf) -> Result<()> {
    if !folder.is_dir() {
        bail!("source path '{}' is not a directory", folder.display());
    }

    let full_backup_folder_path: PathBuf = create_folder_in_backup_structure(&folder)?;

    for file in WalkDir::new(&folder).max_depth(1) {
        let file = file?;
        if PathBuf::from(file.path()).is_dir() {
            if file.path().canonicalize()? != folder.canonicalize()? {
                backup_folder(file.path().to_path_buf())?;
            }
            continue;
        }
        let entry_path = file.path().to_path_buf();

        copy_file_from_folder(entry_path.to_path_buf(), &full_backup_folder_path)?;
    }

    return Ok(());
}

fn create_folder_in_backup_structure<T: AsRef<Path>>(source_path_folder: T) -> io::Result<PathBuf> {
    let source_path_folder: PathBuf = PathBuf::from(source_path_folder.as_ref());
    let backup_folder_path: PathBuf = PathBuf::from(BACKUP_FOLDER_PATH);

    let relative_source_path: PathBuf = PathBuf::from(
        source_path_folder
            .strip_prefix(Component::RootDir)
            .unwrap_or(&source_path_folder), // unwrap_or returns the default value if the strip_prefix was not able to remove any RootDir component.
    );

    let full_backup_folder_path: PathBuf = backup_folder_path.join(relative_source_path);

    fs::create_dir_all(&full_backup_folder_path)?;

    return Ok(full_backup_folder_path);
}

pub fn zip_files_in_folder() -> io::Result<PathBuf> {
    let folder = Path::new(BACKUP_FOLDER_PATH);
    let now = Local::now();

    let timestamp = now.format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename: String = format!("{}-{}.tar", folder.display(), timestamp);

    let tar_file = match File::create(&filename) {
        Ok(file) => file,
        Err(err) => {
            eprintln!(
                "Failed to create the archive file named {}: {}",
                filename, err
            );
            return Err(err);
        }
    };

    let mut archive: Builder<File> = Builder::new(tar_file);

    if let Err(err) = archive.append_dir_all(BACKUP_FOLDER_PATH, BACKUP_FOLDER_PATH) {
        eprintln!(
            "Failed to append directory {} to archive: {}",
            BACKUP_FOLDER_PATH, err
        );
        return Err(err);
    }

    if let Err(err) = archive.finish() {
        eprintln!("Failed to finish archive {}: {}", filename, err);
        return Err(err);
    }

    if let Err(err) = remove_dir_all(BACKUP_FOLDER_PATH) {
        println!(
            "Failed to remove backup folder {}: {}",
            BACKUP_FOLDER_PATH, err
        );
    }

    return Ok(PathBuf::from(filename));
}

pub fn encrypt_file<P: AsRef<Path>>(input_file_path: P, public_key: String) -> Result<()> {
    let output_filename: PathBuf = input_file_path.as_ref().with_extension("tar.age");

    let recipient = x25519::Recipient::from_str(&public_key).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid age recipient \"{public_key}\": {e}"),
        )
    })?;

    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .expect("recipient iterator is non-empty");

    let mut input_file: BufReader<File> = BufReader::new(File::open(&input_file_path)?);
    let output_file: BufWriter<File> = BufWriter::new(File::create(output_filename)?);

    let mut encrypted_output_file: age::stream::StreamWriter<BufWriter<File>> = encryptor
        .wrap_output(output_file)
        .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;

    io::copy(&mut input_file, &mut encrypted_output_file)?;
    encrypted_output_file.finish()?;

    remove_file(input_file_path)?;

    return Ok(());
}
