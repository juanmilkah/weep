use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Password {
    pub service: String,
    pub password: String,
}

#[derive(Debug, Clone)]
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
        Passwords {
            passwords: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, password: Password) {
        self.passwords
            .entry(password.service.clone())
            .or_insert(password);
    }

    pub fn list(&self) {
        if self.passwords.is_empty() {
            println!("No saved Passwords!");
            return;
        }
        for val in self.passwords.iter() {
            println!("{:?}", val);
        }
    }

    pub fn search(&self, service_name: &str) -> Option<Password> {
        self.passwords.get(service_name).cloned()
    }
}
