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
    key_file_exists(&key_filepath);

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
        ("1", "Add a new password"),
        ("2", "Retrieve a password"),
        ("3", "List all services"),
        ("4", "Update Service Password"),
        ("5", "Delete Sevice Password"),
        ("6", "Change Master Key"),
        ("7", "Exit"),
    ]);

    let mut database = Passwords::new(passwords_filepath);

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
                5 => match delete_password(database.clone()) {
                    Ok(db) => {
                        database = db;
                        continue;
                    }
                    Err(e) => handle_error(Box::new(e)),
                },
                6 => match change_master_key(master_key.clone()) {
                    Ok(_) => continue,
                    Err(e) => handle_error(Box::new(e)),
                },
                7 => {
                    println!("Goodbye!");
                    process::exit(0);
                }
                _ => {
                    println!("Invalid Choice! {choice}");
                    continue;
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

fn key_file_exists(filepath: &str) {
    if File::open(filepath).is_err() {
        File::create(filepath).expect("Failed to create key file");
    }
}
