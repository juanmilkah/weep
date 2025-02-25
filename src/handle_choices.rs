/// Weep, A Commandline Password Manager
/// Copyright (C) 2025 Juan Milkah
use std::io::{self, Result, Write};

use bcrypt::{hash, DEFAULT_COST};
use rpassword::prompt_password;

use crate::file_encryption::encrypt_file;
use crate::master_keys::MasterKey;
use crate::passwords::{Password, Passwords};
use crate::{validate_master_key, write_to_file};

pub fn add_password(master_key: &MasterKey, mut database: Passwords) -> io::Result<Passwords> {
    let service_name = prompt("Service Name -> ")?;
    let service_password = prompt("Service_password -> ")?;
    let new_password = Password::new(&service_name, &service_password);

    database.add(new_password.clone());
    let serialized_bytes = bincode::serialize(&database.passwords).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize database passwords: {err}"),
        )
    })?;

    encrypt_file(&master_key.key, &serialized_bytes, &database.filepath)?;

    println!("Password Saved!");
    Ok(database)
}

pub fn retrieve_password(database: &Passwords) -> Result<()> {
    let service_name = prompt("Enter service name: ")?;
    match database.search(&service_name) {
        Some(service) => println!("Password -> {:?}", service.password),
        None => println!("Service not found"),
    }
    Ok(())
}

pub fn update_password(master_key: &MasterKey, mut database: Passwords) -> Result<Passwords> {
    let service_name = prompt("Enter Service Name: ")?;
    match database.search(&service_name) {
        Some(val) => println!("Current Password -> {:?}", val.password),
        None => {
            println!("Service not found!");
            return Ok(database);
        }
    }

    let new_password = prompt("Enter a new password -> ")?;
    let new_password = Password {
        service: service_name,
        password: new_password,
    };

    database.add(new_password.clone());

    let serialized_bytes = bincode::serialize(&database.passwords).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize database passwords: {err}"),
        )
    })?;

    encrypt_file(&master_key.key, &serialized_bytes, &database.filepath)?;

    println!("Password Updated!");

    Ok(database)
}

pub fn list_passwords(database: &Passwords) -> io::Result<()> {
    match database.list() {
        Some(list) => {
            println!("Services:");
            let mut index = 1;
            for pass in list {
                println!("{index}: {:?}", pass.1.service);
                index += 1;
            }
        }
        None => {
            println!("No passwords saved in database");
        }
    }

    Ok(())
}

pub fn change_master_key(master_key: MasterKey, database: Passwords) -> Result<MasterKey> {
    let mut validated = false;
    let mut count = 2;

    while count != 0 && !validated {
        let old_key = prompt_password("Enter current Master key -> ")?;

        let mut cloned_master_key = master_key.clone();
        cloned_master_key.key = old_key;
        if validate_master_key(cloned_master_key)? {
            validated = true;
            break;
        }
        count -= 1;
        eprintln!("Wrong Master key! {} atempts remaining!", count);
    }
    if !validated {
        eprintln!("Too many incorrect attempts!");
        return Ok(master_key);
    }

    let new_key = prompt_password("Enter new Master Key -> ")?;
    let second_key = prompt_password("Re-Enter the New Master Key -> ")?;
    if new_key != second_key {
        eprintln!("Passwords do not match!");
        return Ok(master_key);
    }
    let hashed_key = hash_password(&new_key)?;

    write_to_file(&master_key.filepath, hashed_key)?;

    let serialized_bytes = bincode::serialize(&database.passwords).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize passwords: {err}"),
        )
    })?;

    encrypt_file(&new_key, &serialized_bytes, &database.filepath)?;

    println!("Master Key successfully updated!");

    Ok(MasterKey {
        key: new_key,
        filepath: master_key.filepath,
    })
}

pub fn delete_password(master_key: &MasterKey, mut database: Passwords) -> Result<Passwords> {
    let service_name = prompt("Enter service name to Delete -> ")?;
    let confirm = prompt("Are you sure(yes/no) -> ")?;

    match confirm.to_lowercase().as_str() {
        "y" | "yes" => match database.search(&service_name) {
            Some(_) => {
                database.delete(&service_name);

                let serialized_bytes = bincode::serialize(&database.passwords).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to serialize passwords: {err}"),
                    )
                })?;

                encrypt_file(&master_key.key, &serialized_bytes, &database.filepath)?;

                println!("Password deleted!");
            }
            None => eprintln!("Password does not exist!"),
        },
        "n" | "no" => {
            println!("Password not deleted!");
            return Ok(database);
        }
        _ => {
            eprintln!("Wrong Input!");
            return Ok(database);
        }
    }

    Ok(database)
}

fn prompt(message: &str) -> io::Result<String> {
    print!("{message}");
    io::stdout().flush().map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to flush stdout:{err}"),
        )
    })?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Failed to read input: {err}"),
        )
    })?;

    Ok(input.trim().to_string())
}

pub fn hash_password(password: &str) -> Result<String> {
    let hashed_pass = hash(password, DEFAULT_COST).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to hash password: {err}"),
        )
    })?;

    Ok(hashed_pass)
}
