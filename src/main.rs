mod ascii_art;
mod config;
mod handle_choices;
mod passwords;
mod utils;

use self::ascii_art::draw_ascii;
use self::passwords::Passwords;
use self::utils::handle_error;
use crate::handle_choices::{add_password, list_passwords, retrieve_password, update_password};

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::process;

fn main() {
    draw_ascii();

    let options = BTreeMap::from([
        ("1", "Add a new password"),
        ("2", "Retrieve a password"),
        ("3", "List all services"),
        ("4", "Update Service Password"),
        ("5", "Exit"),
    ]);

    let mut database = Passwords::new();

    loop {
        println!("Choose an option: \n");
        for (key, value) in &options {
            println!("{key}\t{value}");
        }

        let choice = prompt("Your Choice:".to_string());

        match choice.parse().unwrap() {
            1 => match add_password(database.clone()) {
                Ok(db) => {
                    database = db;
                    continue;
                }
                Err(e) => handle_error(Box::new(e)),
            },
            2 => match retrieve_password(&database) {
                Ok(_) => continue,
                Err(e) => handle_error(Box::new(e)),
            },
            3 => match list_passwords(&database) {
                Ok(_) => continue,
                Err(e) => handle_error(Box::new(e)),
            },
            4 => match update_password(database.clone()) {
                Ok(db) => {
                    database = db;
                    continue;
                }
                Err(e) => handle_error(Box::new(e)),
            },
            5 => process::exit(0),
            _ => {
                println!("{choice}");
                process::exit(1)
            }
        }
    }
}

fn prompt(message: String) -> String {
    println!("{message}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}
