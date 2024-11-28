use std::error::Error;
use std::process;

use crate::config::Config;

pub fn handle_error(e: Box<dyn Error>) {
    let cfg = Config::new();

    match cfg.env.as_str() {
        "development" => eprintln!("{e}"),
        _ => eprintln!("Internal Server Error"),
    }

    process::exit(1);
}
