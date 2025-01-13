/// Weep, A Commandline Password Manager
/// Copyright (C) 2025 Juan Milkah
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Password {
    pub service: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passwords {
    pub passwords: Database,
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

pub type Database = BTreeMap<String, Password>;

impl Passwords {
    pub fn new(passwords: Database, filepath: String) -> Self {
        Passwords {
            passwords,
            filepath,
        }
    }

    pub fn add(&mut self, password: Password) {
        self.passwords.insert(password.service.clone(), password);
    }

    pub fn list(&self) -> Option<Database> {
        if self.passwords.is_empty() {
            None
        } else {
            Some(self.passwords.clone())
        }
    }

    pub fn search(&self, service_name: &str) -> Option<Password> {
        self.passwords.get(service_name).cloned()
    }

    pub fn delete(&mut self, service_name: &str) {
        let _ = self.passwords.remove(service_name);
    }
}
