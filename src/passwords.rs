use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Result, Write};
use std::path::PathBuf;

use home::home_dir;
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

    pub fn list(&self) -> Option<Passwords> {
        match read_passwords() {
            Ok(list) => Some(list),
            Err(_) => None,
        }
    }

    pub fn search(&self, service_name: &str) -> Option<Password> {
        self.passwords.get(service_name).cloned()
    }
}

pub fn read_passwords() -> Result<Passwords> {
    let home_directory = get_home_dir();
    let filepath = home_directory.join("weep/passwords.json");
    let file = fs::OpenOptions::new().read(true).open(&filepath);
    let mut file = match file {
        Ok(v) => v,
        Err(_) => fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .open(filepath)
            .unwrap(),
    };
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let passwords: BTreeMap<String, Password> = serde_json::from_str(&content)?;
    Ok(Passwords { passwords })
}

pub fn write_passwords(passwords: BTreeMap<String, Password>) -> Result<()> {
    let json_string = serde_json::to_string_pretty(&passwords)?;

    let home_directory = get_home_dir();
    let filepath = home_directory.join("weep/passwords.json");
    let mut file = fs::OpenOptions::new().write(true).open(filepath)?;
    file.write_all(json_string.as_bytes())?;
    Ok(())
}

fn get_home_dir() -> PathBuf {
    home_dir().unwrap()
}
