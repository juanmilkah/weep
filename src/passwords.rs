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
    pub filepath: String,
}

impl Password {
    pub fn new(key: &str, value: &str) -> Self {
        Password {
            service: key.to_string(),
            password: value.to_string(),
        }
    }
}

impl Passwords {
    pub fn new(filepath: String) -> Self {
        let passwords = read_passwords(&filepath).unwrap();
        Passwords {
            passwords,
            filepath,
        }
    }

    pub fn add(&mut self, password: Password) {
        self.passwords.insert(password.service.clone(), password);
        write_passwords(self.passwords.clone(), &self.filepath).unwrap();
    }

    pub fn list(&self) -> Option<BTreeMap<String, Password>> {
        match read_passwords(&self.filepath) {
            Ok(list) => Some(list),
            Err(_) => None,
        }
    }

    pub fn search(&self, service_name: &str) -> Option<Password> {
        self.passwords.get(service_name).cloned()
    }

    pub fn delete(&mut self, service_name: &str) {
        let _ = self.passwords.remove(service_name);
        write_passwords(self.passwords.clone(), &self.filepath).unwrap();
    }
}

pub fn read_passwords(filepath: &str) -> Result<BTreeMap<String, Password>> {
    let file = fs::OpenOptions::new().read(true).open(filepath);
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

    if content.is_empty() {
        return Ok(BTreeMap::new());
    }

    let passwords: BTreeMap<String, Password> = serde_json::from_str(&content)?;
    Ok(passwords)
}

pub fn write_passwords(passwords: BTreeMap<String, Password>, filepath: &str) -> Result<()> {
    let json_string = serde_json::to_string_pretty(&passwords)?;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(filepath)?;
    file.write_all(json_string.as_bytes())?;
    Ok(())
}
