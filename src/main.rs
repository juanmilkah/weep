/// Weep, A Commandline Password Manager
/// Copyright (C) 2025 Juan Milkah
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
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::process;

fn main() -> io::Result<()> {
    draw_ascii();
    let mut validated = false;

    let (key_filepath, passwords_filepath) = get_file_paths()?;

    let mut master_key: MasterKey = MasterKey::default();
    if !key_exists(&key_filepath)? {
        master_key = create_new_master_key(&key_filepath)?;
        validated = true;
    }

    if !validated {
        master_key = validate_master_key_loop(key_filepath)?;
    }

    let database = decrypt_file(&master_key.key, &passwords_filepath)?;

    let database = Passwords::new(database, passwords_filepath.clone());

    /*main program */
    run(database, master_key)?;

    Ok(())
}

fn run(mut database: Passwords, mut master_key: MasterKey) -> io::Result<()> {
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

        let choice = prompt("Your Choice:".to_string())?;

        match choice.to_lowercase().chars().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Failed to get first input char",
            )
        })? {
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

fn validate_master_key_loop(key_filepath: String) -> io::Result<MasterKey> {
    loop {
        let key = prompt_password("Enter master Key: ").map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Failed toread key file: {}", err),
            )
        })?;

        let ll_master_key = MasterKey::new(&key, key_filepath.clone());
        if validate_master_key(ll_master_key.clone())? {
            return Ok(ll_master_key);
        } else {
            eprintln!("Wrong master Key");
        }
    }
}

fn handle_exit(master_key: MasterKey, database: Passwords) {
    println!("Wait a minute...");
    //convert the database to bytes

    let serialized_bytes = bincode::serialize(&database.passwords)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialise passwords: {}", err),
            )
        })
        .unwrap_or_else(|e| {
            eprintln!("{e}");
            process::exit(1);
        });

    if let Err(e) = encrypt_file(&master_key.key, &serialized_bytes, &database.filepath) {
        eprintln!("{e}");
        process::exit(1);
    }

    println!("Goodbye!");
    process::exit(0);
}

fn prompt(message: String) -> io::Result<String> {
    println!("{message}");
    io::stdout().flush().map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to flush stdout: {}", err),
        )
    })?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Failed to read input: {}", err),
        )
    })?;

    Ok(input.trim().to_string())
}

fn validate_master_key(master_key: MasterKey) -> io::Result<bool> {
    let content = read_from_file(&master_key.filepath)?;
    if content.is_empty() {
        let pass_hash = hash(&master_key.key, DEFAULT_COST).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to hash key: {}", err),
            )
        })?;

        write_to_file(&master_key.filepath, pass_hash)?;
        return Ok(true);
    }

    let is_valid = verify(&master_key.key, &content).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to verify master key: {}", err),
        )
    })?;

    Ok(is_valid)
}

pub fn read_from_file(filepath: &str) -> io::Result<String> {
    let mut file =
        BufReader::new(File::open(filepath).expect("Failed to open file in read-only mode"));
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    Ok(content)
}

pub fn write_to_file(filepath: &str, content: String) -> io::Result<()> {
    let mut file =
        BufWriter::new(File::create(filepath).expect("Failed to open file in write-only mode"));
    let _ = file.write_all(content.as_bytes()).map_err(|err| {
        eprintln!("Failed to write bytes to file: {err}");
    });
    Ok(())
}

fn key_exists(filepath: &str) -> io::Result<bool> {
    let content = read_from_file(filepath).map_err(|err| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to read key file: {}", err),
        )
    })?;

    Ok(!content.is_empty())
}

fn create_new_master_key(key_filepath: &str) -> io::Result<MasterKey> {
    println!("No Master Key exists!\nCreate a new Master Key!");
    let new_key = prompt_password("Enter new Master Key: ").map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Failed to read master key: {}", err),
        )
    })?;

    let rep_key = prompt_password("Re-Enter the Master Key: ").map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Failed to read master key: {}", err),
        )
    })?;

    if new_key != rep_key {
        eprintln!("Key's does not match!");
        process::exit(0);
    }

    let master_key = MasterKey::new(&new_key, key_filepath.to_string());
    let hashed_key = hash_password(&new_key).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to hash master key: {}", err),
        )
    })?;

    write_to_file(key_filepath, hashed_key.to_string()).expect("Failed to write into key file");
    println!("New Master Key successfully Created!");
    Ok(master_key)
}

fn get_file_paths() -> io::Result<(String, String)> {
    let home = home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home Directory not Found"))?;

    let get_path = |filename: &str| -> String {
        home.join(".weeprc")
            .join(filename)
            .to_string_lossy()
            .into_owned()
    };

    let key_filepath = get_path("key");
    let passwords_filepath = get_path("passwords");

    Ok((key_filepath, passwords_filepath))
}
