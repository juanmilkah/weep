mod ascii_art;
mod config;
mod file_encryption;
mod handle_choices;
mod master_keys;
mod passwords;
mod utils;

use bcrypt::{hash, verify, DEFAULT_COST};
use home::home_dir;
use rpassword::prompt_password;

use self::ascii_art::draw_ascii;
use self::file_encryption::{decrypt_file, encrypt_file};
use self::handle_choices::{change_master_key, delete_password};
use self::master_keys::MasterKey;
use self::passwords::Passwords;
use self::utils::handle_error;
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

    while !validated {
        let key = prompt_password("Enter master Key: ").unwrap();
        let ll_master_key = MasterKey::new(&key, key_filepath.clone());
        if !validate_master_key(ll_master_key.clone()).unwrap() {
            eprintln!("Wrong master Key");
            continue;
        } else {
            validated = true;
            master_key = ll_master_key;
        }
    }

    let options = BTreeMap::from([
        ("a", "Add a new password"),
        ("r", "Retrieve a password"),
        ("l", "List all services"),
        ("u", "Update Service Password"),
        ("d", "Delete Sevice Password"),
        ("c", "Change Master Key"),
        ("q", "Exit"),
    ]);

    decrypt_file(&master_key.key, &passwords_filepath, &passwords_filepath)
        .expect("Failed to decrypt database");

    let mut database = Passwords::new(passwords_filepath.clone());

    loop {
        println!("Choose an option: ");
        for (key, value) in &options {
            println!("{key}\t{value}");
        }

        let choice = prompt("Your Choice:".to_string());

        match choice.to_lowercase().chars().next().unwrap() {
            'a' => match add_password(database.clone()) {
                Ok(db) => {
                    database = db;
                    continue;
                }
                Err(e) => handle_error(Box::new(e)),
            },
            'r' => match retrieve_password(&database) {
                Ok(_) => continue,
                Err(e) => handle_error(Box::new(e)),
            },
            'l' => match list_passwords(&database) {
                Ok(_) => continue,
                Err(e) => handle_error(Box::new(e)),
            },
            'u' => match update_password(database.clone()) {
                Ok(db) => {
                    database = db;
                    continue;
                }
                Err(e) => handle_error(Box::new(e)),
            },
            'd' => match delete_password(database.clone()) {
                Ok(db) => {
                    database = db;
                    continue;
                }
                Err(e) => handle_error(Box::new(e)),
            },
            'c' => match change_master_key(master_key.clone()) {
                Ok(new_master_key) => master_key = new_master_key,
                Err(e) => handle_error(Box::new(e)),
            },
            'q' => handle_exit(master_key.clone(), &passwords_filepath),
            _ => {
                println!("Invalid Choice!");
                continue;
            }
        }
    }
}

fn handle_exit(master_key: MasterKey, filepath: &str) {
    println!("Wait a minute...");
    encrypt_file(&master_key.key, filepath, filepath).expect("Failed to encrypt passwords");
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
