use std::io::{self, Write};

use crate::passwords::{Password, Passwords};

pub fn add_password(mut database: Passwords) -> io::Result<Passwords> {
    let service_name = prompt("Service Name: ");
    let service_password = prompt("Service_password: ");
    let new_password = Password::new(&service_name, &service_password);

    database.add(new_password.clone());

    println!(
        "Added new password!\n{:?}\t{:?}",
        new_password.service, new_password.password
    );
    Ok(database)
}

pub fn retrieve_password() {}

pub fn update_password() {}

pub fn list_passwords(database: &Passwords) -> io::Result<()> {
    database.list();
    Ok(())
}

fn prompt(message: &str) -> String {
    print!("{message}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}
