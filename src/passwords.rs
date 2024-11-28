#[derive(Debug, Clone)]
pub struct Password {
    pub service: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct Passwords {
    pub passwords: Vec<Password>,
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
            passwords: Vec::new(),
        }
    }

    pub fn add(&mut self, password: Password) {
        self.passwords.push(password);
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
}
