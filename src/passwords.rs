use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Result, Write};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Password {
    pub service: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passwords {
    pub passwords: BTreeMap<String, Password>,
}

impl Password {
    pub fn new(key: &str, value: &str) -> Password {
        Password {
            service: key.to_string(),
            password: value.to_string(),
        }
    }
}

impl Passwords {
    pub fn new() -> Passwords {
        read_passwords().unwrap()
    }

    pub fn add(&mut self, password: Password) {
        self.passwords.insert(password.service.clone(), password);
        write_passwords(self.passwords.clone()).unwrap();
    }

    pub fn list(&self) {
        if let Ok(pass_list) = read_passwords() {
            for pass in pass_list.passwords {
                println!("{:?}", pass.1); //key, value
            }
        }
    }

    pub fn search(&self, service_name: &str) -> Option<Password> {
        self.passwords.get(service_name).cloned()
    }
}

pub fn read_passwords() -> Result<Passwords> {
    let mut file = fs::OpenOptions::new().read(true).open("passwords.json")?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let passwords: BTreeMap<String, Password> = serde_json::from_str(&content)?;
    Ok(Passwords { passwords })
}

pub fn write_passwords(passwords: BTreeMap<String, Password>) -> Result<()> {
    let json_string = serde_json::to_string_pretty(&passwords)?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open("passwords.json")?;
    file.write_all(json_string.as_bytes())?;
    Ok(())
}
