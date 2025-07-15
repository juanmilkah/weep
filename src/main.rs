use argon2::{self, Argon2};
use bcrypt::{hash, verify, DEFAULT_COST};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{distributions::Alphanumeric, prelude::Distribution, Rng, RngCore};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{stdin, stdout, BufReader, Read, Write},
    path::{Path, PathBuf},
    process,
};

const DEFAULT_DIRECTORY: &str = ".weeprc";
const USAGE: &str = r#"
    [Weep] 
    Use quotes(") if you explicitly want them included.
    [SubCommands]
    a[dd]        Add a new password
    g[et]        Get a password
    l[ist]       List all services
    u[update]    Update Service Password
    d[elete]     Delete Sevice Password
    c[change]    Change Master Key
    s[ave]       Flush the changes to disk
    q[uit]       Exit
    h[elp]       Show help and usage"#;

fn draw_ascii() {
    let art = "                                                                                               
 ▄█     █▄     ▄████████    ▄████████    ▄███████▄ 
███     ███   ███    ███   ███    ███   ███    ███ 
███     ███   ███    █▀    ███    █▀    ███    ███ 
███     ███  ▄███▄▄▄      ▄███▄▄▄       ███    ███ 
███     ███ ▀▀███▀▀▀     ▀▀███▀▀▀     ▀█████████▀  
███     ███   ███    █▄    ███    █▄    ███        
███ ▄█▄ ███   ███    ███   ███    ███   ███        
 ▀███▀███▀    ██████████   ██████████  ▄████▀      
";

    println!("{art}");
}

fn change_key_passphrase(master_key: &mut MasterKey) -> Result<Option<SecureString>, String> {
    let mut count = 3;
    let mut validated = false;

    while count > 0 {
        let old_passphrase = prompt_password("Enter current Passphrase -> ")
            .map_err(|err| format!("Error: Prompt password: {err}"))?;

        if verify(old_passphrase, &master_key.passphrase_hash)
            .map_err(|err| format!("Error: verify passphrase: {err}"))?
        {
            validated = true;
            break;
        }

        count -= 1;
        eprintln!("Wrong Passphrase! {count} atempts remaining!");
    }

    if !validated {
        eprintln!("Too many incorrect attempts!");
        return Ok(None);
    }

    let new_passphrase = prompt_password("Enter new passphrase -> ")
        .map_err(|err| format!("Error: Prompt passphrase: {err}"))?;
    let passphrase_rep = prompt_password("Repeat new passphrase -> ")
        .map_err(|err| format!("Error: Prompt passphrase: {err}"))?;

    if new_passphrase != passphrase_rep {
        eprintln!("Passphrases do not match!");
        return Ok(None);
    }
    let hashed_key = hash_password(&new_passphrase)?;
    let new_key = generate_new_key();
    let encrypted_key = encrypt_content(&new_passphrase, new_key.0.as_bytes())?;

    master_key.passphrase_hash = hashed_key;
    master_key.encrypted_key = encrypted_key;

    println!("Master Key successfully updated!");

    Ok(Some(new_key))
}

fn delete_password(database: &mut Database) -> Result<(), String> {
    let service_name = prompt("Enter service name to Delete -> ")?;
    if service_name.is_empty() {
        eprintln!("Field can't be empty!");
        return Ok(());
    }
    let confirm = prompt("Are you sure(yes/no) -> ")?;

    match confirm.to_lowercase().as_str() {
        "yes" => match database.search(&service_name) {
            Some(_) => {
                database.delete(&service_name);

                println!("Password deleted!");
            }
            None => eprintln!("Password does not exist!"),
        },
        _ => {
            println!("Password not deleted!");
        }
    }

    Ok(())
}

fn update_password(database: &mut Database) -> Result<(), String> {
    let service_name = prompt("Enter Service Name: ")?;

    if service_name.is_empty() {
        eprintln!("Field can't be empty!");
        return Ok(());
    }
    match database.search(&service_name) {
        Some(val) => println!("Current Password -> {:?}", val.password.0),
        None => {
            println!("Service not found!");
            return Ok(());
        }
    }

    let service_password = prompt("Enter a new password -> ")?;
    if service_password.is_empty() {
        eprintln!("Field can't be empty!");
        return Ok(());
    }
    let new_pass = Password::new(service_name, service_password);

    database.add(new_pass);

    println!("Password Updated!");

    Ok(())
}

fn list_passwords(database: &Database) {
    match database.list_keys() {
        Some(list) => {
            println!("Services:");
            for (index, key) in list.iter().enumerate() {
                println!("{index}: {key}", index = index + 1);
            }
        }
        None => {
            println!("No passwords saved in database");
        }
    }
}

fn retrieve_password(database: &Database) {
    let service_name = prompt("Enter service name: ").unwrap_or_default();
    if !service_name.is_empty() {
        match database.search(&service_name) {
            Some(service) => println!("Password -> {:?}", service.password.0),
            None => println!("Service not found"),
        }
    } else {
        eprintln!("Field can't be empty!");
    }
}

fn add_password(database: &mut Database) -> Result<(), String> {
    let service_name = prompt("Service Name -> ")?;
    if service_name.is_empty() {
        eprintln!("Field can't be empty!");
        return Ok(());
    }
    let service_password = prompt("Service_password -> ")?;
    if service_password.is_empty() {
        eprintln!("Field can't be empty!");
        return Ok(());
    }

    let new_password = Password::new(service_name, service_password);

    database.add(new_password);

    println!("Password Saved!");
    Ok(())
}

fn prompt(message: &str) -> Result<String, String> {
    print!("{message}");
    stdout().flush().unwrap();

    let mut input = String::new();
    stdin()
        .read_line(&mut input)
        .map_err(|err| format!("Failed to read input: {err}"))?;

    Ok(input.trim().to_string())
}

#[derive(Debug, Serialize, Deserialize)]
struct Password {
    service: String,
    password: SecureString,
}

impl Password {
    fn new(service: String, raw_password: String) -> Self {
        Password {
            service,
            password: SecureString(raw_password),
        }
    }
}

type Collection = HashMap<String, Password>;

#[derive(Debug, Serialize, Deserialize)]
struct Database {
    collection: Collection,
    dirty: bool, // for flushing to disk
}

impl Database {
    fn new() -> Self {
        Database {
            collection: HashMap::new(),
            dirty: false,
        }
    }

    fn add(&mut self, password: Password) {
        self.collection.insert(password.service.clone(), password);
        self.dirty = true;
    }

    fn list_keys(&self) -> Option<Vec<String>> {
        if self.collection.is_empty() {
            None
        } else {
            Some(self.collection.keys().map(|k| k.to_owned()).collect())
        }
    }

    fn search(&self, service_name: &str) -> Option<&Password> {
        self.collection.get(service_name)
    }

    fn delete(&mut self, service_name: &str) {
        self.collection.remove(service_name);
        self.dirty = true;
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MasterKey {
    passphrase_hash: String,
    encrypted_key: Vec<u8>,
}

impl MasterKey {
    fn new(passphrase_hash: String, encrypted_key: Vec<u8>) -> Self {
        Self {
            passphrase_hash,
            encrypted_key,
        }
    }
}

fn read_from_file(filepath: &Path) -> Result<Vec<u8>, String> {
    let file = File::options()
        .read(true)
        .open(filepath)
        .map_err(|err| format!("Error: Open {filepath:?} for reading: {err}"))?;
    let mut file = BufReader::new(file);
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|err| format!("Error: read {filepath:?}: {err}"))?;

    Ok(buf)
}

fn hash_password(password: &str) -> Result<String, String> {
    let hashed_pass =
        hash(password, DEFAULT_COST).map_err(|err| format!("Error: hash password: {err}"))?;

    Ok(hashed_pass)
}

fn decrypt_content(password: &str, content: Vec<u8>) -> Result<Vec<u8>, String> {
    assert!(content.len() > 16 + 12); // salt + salt

    // Extract the salt, nonce, and ciphertext
    let (salt, rest) = content.split_at(16);
    let (nonce, ciphertext) = rest.split_at(12);

    // Derive the decryption key
    let key = derive_key(password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    // Decrypt the content
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|err| format!("Error: decryption: {err}"))?;
    Ok(plaintext)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut output_key_material = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
        .map_err(|err| format!("Failed to derive key: {err}"))?;
    Ok(output_key_material)
}

fn encrypt_content(password: &str, content: &[u8]) -> Result<Vec<u8>, String> {
    // Generate a random salt for key derivation
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive the encryption key
    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    // Generate a random nonce for encryption
    let nonce = Nonce::from(rand::thread_rng().gen::<[u8; 12]>());

    // Encrypt the content
    let mut ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: content,
                aad: &[],
            },
        )
        .map_err(|err| format!("Failed to encrypt payload: {err}"))?;

    // Write the salt, nonce, and ciphertext to the output file
    // [salt.., nonce.., cyphertext..];
    let mut data: Vec<u8> = salt.to_vec();
    data.append(&mut nonce.to_vec());
    data.append(&mut ciphertext);
    Ok(data)
}

fn write_to_file(filepath: &Path, content: &[u8]) -> Result<(), String> {
    let mut file = File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(filepath)
        .map_err(|err| format!("Error: Open file {filepath:?} for write: {err}"))?;
    file.write_all(content)
        .map_err(|err| format!("Error: write content to file {filepath:?}: {err}"))?;
    Ok(())
}

fn generate_new_key() -> SecureString {
    let mut rng = rand::thread_rng();

    let key: String = Alphanumeric
        .sample_iter(&mut rng)
        .take(32)
        .map(char::from)
        .collect();

    SecureString(key)
}

/// Prompts user for a new passphrase with which is used to
/// generate a new master key
fn create_new_master_key(key_filepath: &Path) -> Result<SecureString, String> {
    println!("No Master Key exists!\nCreate a new Master Key!");
    let passphrase = prompt_password("Enter passphrase for new master key: ")
        .map_err(|err| format!("Failed to read passphrase: {err}"))?;

    let passphrase_rep = prompt_password("Re-Enter the passphrase: ")
        .map_err(|err| format!("Failed to read passphrase: {err}"))?;

    if passphrase_rep != passphrase {
        eprintln!("Passpharases do'nt match");
        process::exit(0);
    }

    let new_key = generate_new_key();
    let passphrase_hash = hash_password(&passphrase)?;
    let encrypted_key = encrypt_content(&passphrase, new_key.0.as_bytes())?;
    let master_key = MasterKey::new(passphrase_hash, encrypted_key);
    let serialized_key = bincode2::serialize(&master_key)
        .map_err(|err| format!("Error: Serialize master key: {err}"))?;

    write_to_file(key_filepath, &serialized_key)?;
    println!("New Master Key successfully Created!");
    Ok(new_key)
}

/// Validates the user passphrase;
/// and decrypts the master key;
fn validate_passphrase(key_filepath: &Path) -> Result<SecureString, String> {
    let content = read_from_file(key_filepath)?;
    if content.is_empty() {
        let master_key = create_new_master_key(key_filepath)?;
        return Ok(master_key);
    }

    let master: MasterKey = bincode2::deserialize(&content)
        .map_err(|err| format!("Error: deserialize master: {err}"))?;

    loop {
        let key = prompt_password("Enter passphrase: ")
            .map_err(|err| format!("Failed to read passphrase: {err}"))?;

        if verify(key.clone(), &master.passphrase_hash)
            .map_err(|err| format!("Error: Verify passphrase: {err}"))?
        {
            let decrypted_key = decrypt_content(&key, master.encrypted_key)?;
            return Ok(SecureString(String::from_utf8(decrypted_key).unwrap()));
        }

        println!("No key found with the passphrase");
    }
}

/// Checks if the default `weeprc` directory exists
/// Creates the `key` && `passwords` files if they do not exist
fn get_file_paths() -> Result<(PathBuf, PathBuf), String> {
    let home = home::home_dir().unwrap();
    let default_dir = home.join(DEFAULT_DIRECTORY);

    if !default_dir.exists() {
        fs::create_dir(&default_dir).map_err(|err| format!("Error: Create default dir: {err}"))?;
    }

    let get_path = |filename: &str| -> PathBuf { default_dir.join(filename) };

    let key_filepath = get_path("key");
    let passwords_filepath = get_path("passwords");

    if !key_filepath.exists() {
        let _ =
            File::create(&key_filepath).map_err(|err| format!("Error: Create key file: {err}"))?;
    }

    if !passwords_filepath.exists() {
        let _ = File::create(&passwords_filepath)
            .map_err(|err| format!("Error: Create database file: {err}"))?;
    }
    Ok((key_filepath, passwords_filepath))
}

struct Config {
    key_filepath: PathBuf,
    passwords_filepath: PathBuf,
    decrypted_key: SecureString,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
struct SecureString(String);

/// initial setup; Gets the necessary filepaths and validates the
/// users passphrase
fn init() -> Result<Config, String> {
    let (key_filepath, passwords_filepath) = get_file_paths()?;

    let decrypted_key = validate_passphrase(&key_filepath)?;

    Ok(Config {
        key_filepath,
        passwords_filepath,
        decrypted_key,
    })
}

fn run(cfg: &mut Config) -> Result<(), String> {
    println!("{USAGE}");

    let mut database: Database = {
        let encrypted_database = read_from_file(&cfg.passwords_filepath)?;
        if encrypted_database.is_empty() {
            Database::new()
        } else {
            let decrypted_database = decrypt_content(&cfg.decrypted_key.0, encrypted_database)?;
            bincode2::deserialize(&decrypted_database)
                .map_err(|err| format!("Error: deserialize database: {err}"))?
        }
    };

    let flush_to_disk = |database: &mut Database, cfg: &mut Config| -> Result<(), String> {
        let serialized_database = bincode2::serialize(&database)
            .map_err(|err| format!("Error: Serialize database: {err}"))?;
        let encrypted_database = encrypt_content(&cfg.decrypted_key.0, &serialized_database)?;
        let mut file = File::options()
            .write(true)
            .truncate(true)
            .open(&cfg.passwords_filepath)
            .map_err(|err| format!("Error: Open database file for write: {err}"))?;
        file.write_all(&encrypted_database)
            .map_err(|err| format!("Error: Write database to file: {err}"))?;
        database.dirty = false;
        Ok(())
    };

    loop {
        let subcommand = prompt("==> ")?;
        stdout().flush().unwrap();
        if subcommand.is_empty() {
            continue;
        }

        match subcommand.to_lowercase().chars().next().unwrap() {
            // add new
            'a' => {
                if let Err(e) = add_password(&mut database) {
                    eprintln!("{e}");
                    continue;
                }
            }

            // change master key
            'c' => {
                let mut file = File::options()
                    .read(true)
                    .open(&cfg.key_filepath)
                    .map_err(|err| format!("Error: Open key filepath for reading: {err}"))?;
                let mut master: MasterKey = bincode2::deserialize_from(&mut file)
                    .map_err(|err| format!("Error: deserialize master: {err}"))?;

                match change_key_passphrase(&mut master) {
                    Ok(Some(new_key)) => {
                        cfg.decrypted_key = new_key;
                    }
                    Ok(None) => continue,
                    Err(err) => {
                        eprintln!("Error: Change key passphrase: {err}");
                        continue;
                    }
                }

                let mut file = File::options()
                    .write(true)
                    .truncate(true)
                    .open(&cfg.key_filepath)
                    .map_err(|err| format!("Error: Open key filepath for writing: {err}"))?;

                bincode2::serialize_into(&mut file, &master)
                    .map_err(|err| format!("Error: Serialize into key filepath: {err}"))?;
                flush_to_disk(&mut database, cfg)?;
            }

            // delete
            'd' => {
                if let Err(e) = delete_password(&mut database) {
                    eprintln!("Failed to delete passwords! {e:?}");
                    continue;
                }
            }
            // get
            'g' => retrieve_password(&database),

            // help
            'h' => println!("{USAGE}"),
            // list
            'l' => list_passwords(&database),
            // quit | exit
            'q' | 'e' => break,
            // save
            's' => flush_to_disk(&mut database, cfg)?,
            // update
            'u' => {
                if let Err(e) = update_password(&mut database) {
                    eprintln!("Failed to update password! {e:?}");
                    continue;
                }
            }

            _ => eprintln!("Invalid SubCommand!"),
        }
    }

    if database.dirty {
        flush_to_disk(&mut database, cfg)?;
    }

    Ok(())
}

fn main() -> Result<(), String> {
    draw_ascii();
    let mut config = init()?;
    run(&mut config)?;

    Ok(())
}
