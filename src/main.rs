mod ascii_art;
mod file_encryption;
mod handle_choices;
mod master_keys;
mod passwords;

use bcrypt::{hash, verify, DEFAULT_COST};
use home::home_dir;
use rpassword::prompt_password;

use self::ascii_art::draw_ascii;
use self::file_encryption::{decrypt_file, encrypt_file};
use self::handle_choices::{change_master_key, delete_password, hash_password};
use self::master_keys::MasterKey;
use self::passwords::Passwords;
use crate::handle_choices::{add_password, list_passwords, retrieve_password, update_password};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::{fs, process};

fn main() {
    draw_ascii();
    let mut validated = false;

    let passwords_filepath = home_dir()
        .unwrap()
        .join("weep/passwords")
        .to_string_lossy()
        .to_string();

    let key_filepath = home_dir()
        .unwrap()
        .join("weep/key")
        .to_string_lossy()
        .to_string();
    file_exists(&key_filepath);
    file_exists(&passwords_filepath);

    let mut master_key: MasterKey = MasterKey::default();
    if !key_exists(&key_filepath) {
        master_key = create_new_master_key(&key_filepath).expect("Failed to create new master key");
        validated = true;
    }

    if !validated {
        master_key = validate_master_key_loop(key_filepath);
    }

    let database =
        decrypt_file(&master_key.key, &passwords_filepath).expect("Failed to decrypt database");

    let database = Passwords::new(database, passwords_filepath.clone());

    /*main program */
    run(database, master_key)
}

fn run(mut database: Passwords, mut master_key: MasterKey) {
    let options = BTreeMap::from([
        ("a", "Add a new password"),
        ("r", "Retrieve a password"),
        ("l", "List all services"),
        ("u", "Update Service Password"),
        ("d", "Delete Sevice Password"),
        ("c", "Change Master Key"),
        ("q", "Exit"),
    ]);

    loop {
        println!("Choose an option: ");
        for (key, value) in &options {
            println!("{key}\t{value}");
        }

        let choice = prompt("Your Choice:".to_string());

        match choice.to_lowercase().chars().next().unwrap() {
            'a' => match add_password(&master_key, database.clone()) {
                Ok(db) => {
                    database = db;
                    continue;
                }
                Err(e) => eprintln!("Failed to add password! {:?}", e),
            },
            'r' => match retrieve_password(&database) {
                Ok(_) => continue,
                Err(e) => eprintln!("Failed to retrive password! {:?}", e),
            },
            'l' => match list_passwords(&database) {
                Ok(_) => continue,
                Err(e) => eprintln!("Failed to list passwords! {:?}", e),
            },
            'u' => match update_password(&master_key, database.clone()) {
                Ok(db) => {
                    database = db;
                    continue;
                }
                Err(e) => eprintln!("Failed to update password! {:?}", e),
            },
            'd' => match delete_password(&master_key, database.clone()) {
                Ok(db) => {
                    database = db;
                    continue;
                }
                Err(e) => eprintln!("Failed to delete passwords! {:?}", e),
            },
            'c' => match change_master_key(master_key.clone(), database.clone()) {
                Ok(new_master_key) => master_key = new_master_key,
                Err(e) => eprintln!("Failed to change master key! {:?}", e),
            },
            'q' => handle_exit(master_key.clone(), database.clone()),
            _ => {
                println!("Invalid Choice!");
                continue;
            }
        }
    }
}

fn validate_master_key_loop(key_filepath: String) -> MasterKey {
    loop {
        let key = prompt_password("Enter master Key: ").unwrap();
        let ll_master_key = MasterKey::new(&key, key_filepath.clone());
        if validate_master_key(ll_master_key.clone()).unwrap_or(false) {
            return ll_master_key;
        } else {
            eprintln!("Wrong master Key");
        }
    }
}

fn handle_exit(master_key: MasterKey, database: Passwords) {
    println!("Wait a minute...");
    //convert the database to bytes

    let serialized_bytes =
        bincode::serialize(&database.passwords).expect("Failed to serialize bytes");
    encrypt_file(&master_key.key, &serialized_bytes, &database.filepath)
        .expect("Failed to encrypt passwords");
    println!("Goodbye!");
    process::exit(0);
}

fn prompt(message: String) -> String {
    println!("{message}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn validate_master_key(master_key: MasterKey) -> io::Result<bool> {
    let content = read_from_file(&master_key.filepath).unwrap();
    if content.is_empty() {
        let pass_hash = hash(&master_key.key, DEFAULT_COST).unwrap();
        write_to_file(&master_key.filepath, pass_hash).unwrap();
        return Ok(true);
    }

    Ok(verify(master_key.key, &content).unwrap_or(false))
}

pub fn read_from_file(filepath: &str) -> io::Result<String> {
    let mut file = fs::OpenOptions::new().read(true).open(filepath)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    Ok(content)
}

pub fn write_to_file(filepath: &str, content: String) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(filepath)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

fn file_exists(filepath: &str) {
    if File::open(filepath).is_err() {
        File::create(filepath).expect("Failed to create key file");
    }
}

fn key_exists(filepath: &str) -> bool {
    let content = read_from_file(filepath).unwrap();
    !content.is_empty()
}

fn create_new_master_key(key_filepath: &str) -> io::Result<MasterKey> {
    println!("No Master Key exists!\nCreate a new Master Key!");
    let new_key = prompt_password("Enter new Master Key: ").unwrap();
    let rep_key = prompt_password("Re-Enter the Master Key: ").unwrap();
    if new_key != rep_key {
        eprintln!("Key's does not match!");
        process::exit(0);
    }

    let master_key = MasterKey::new(&new_key, key_filepath.to_string());
    let hashed_key = hash_password(&new_key).unwrap();

    write_to_file(key_filepath, hashed_key).unwrap();
    println!("New Master Key successfully Created!");
    Ok(master_key)
}
