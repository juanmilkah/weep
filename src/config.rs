use std::env;

#[derive(Debug)]
pub struct Config {
    pub env: String,
}

impl Config {
    pub fn new() -> Config {
        let env = get_env_var("ENVIRONMENT".to_string(), "production".to_string());
        Config { env }
    }
}

fn get_env_var(variable: String, default_value: String) -> String {
    match env::var(variable) {
        Ok(val) => val.to_string(),
        Err(_) => default_value.to_string(),
    }
}
