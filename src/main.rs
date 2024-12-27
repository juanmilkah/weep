mod ascii_art;
mod config;
mod handle_choices;
mod master_keys;
mod passwords;
mod utils;

use bcrypt::{hash, verify, DEFAULT_COST};
use home::home_dir;
use rpassword::prompt_password;

use self::ascii_art::draw_ascii;
use self::handle_choices::change_master_key;
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
    let key_filepath = home_dir()
        .unwrap()
        .join("weep/key.txt")
        .to_string_lossy()
        .to_string();
    key_file_exists(&key_filepath);

    while !validated {
        let key = prompt_password("Enter master Key: ").unwrap();
        let master_key = MasterKey::new(&key);
        if !validate_master_key(&key_filepath, master_key).unwrap() {
            eprintln!("Wrong master Key");
            continue;
        } else {
            validated = true;
        }
    }

    let options = BTreeMap::from([
        ("1", "Add a new password"),
        ("2", "Retrieve a password"),
        ("3", "List all services"),
        ("4", "Update Service Password"),
        ("5", "Change Master Key"),
        ("6", "Exit"),
    ]);

    let mut database = Passwords::new();

    loop {
        println!("Choose an option: ");
        for (key, value) in &options {
            println!("{key}\t{value}");
        }

        let choice = prompt("Your Choice:".to_string());

        match choice.parse() {
            Ok(v) => match v {
                1 => match add_password(database.clone()) {
                    Ok(db) => {
                        database = db;
                        continue;
                    }
                    Err(e) => handle_error(Box::new(e)),
                },
                2 => match retrieve_password(&database) {
                    Ok(_) => continue,
                    Err(e) => handle_error(Box::new(e)),
                },
                3 => match list_passwords(&database) {
                    Ok(_) => continue,
                    Err(e) => handle_error(Box::new(e)),
                },
                4 => match update_password(database.clone()) {
                    Ok(db) => {
                        database = db;
                        continue;
                    }
                    Err(e) => handle_error(Box::new(e)),
                },
                5 => match change_master_key(&key_filepath) {
                    Ok(_) => continue,
                    Err(e) => handle_error(Box::new(e)),
                },
                6 => {
                    println!("Goodbye!");
                    process::exit(0);
                }
                _ => {
                    println!("{choice}");
                    process::exit(1)
                }
            },
            Err(_) => eprintln!("Invalid input"),
        }
    }
}

fn prompt(message: String) -> String {
    println!("{message}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn validate_master_key(filepath: &str, master_key: MasterKey) -> io::Result<bool> {
    let content = read_from_file(filepath).unwrap();
    if content.is_empty() {
        let pass_hash = hash(&master_key.key, DEFAULT_COST).unwrap();
        write_to_file(filepath, pass_hash).unwrap();
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

fn key_file_exists(filepath: &str) {
    if File::open(filepath).is_err() {
        File::create(filepath).expect("Failed to create key file");
    }
}
