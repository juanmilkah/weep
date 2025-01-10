use argon2::{self, Argon2};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::Rng;
use std::fs::File;
use std::io::{Read, Write};

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut output_key_material = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
        .unwrap();
    output_key_material
}

pub fn encrypt_file(password: &str, input_file: &str, output_file: &str) -> std::io::Result<()> {
    // Generate a random salt for key derivation
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);

    // Derive the encryption key
    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    // Generate a random nonce for encryption
    let nonce = Nonce::from(rand::thread_rng().gen::<[u8; 12]>());

    // Read input file content
    let mut input = Vec::new();
    File::open(input_file)?.read_to_end(&mut input)?;

    // Encrypt the content
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &input,
                aad: &[],
            },
        )
        .expect("Encryption failed");

    // Write the salt, nonce, and ciphertext to the output file
    let mut output = File::create(output_file)?;
    output.write_all(&salt)?;
    output.write_all(&nonce)?;
    output.write_all(&ciphertext)?;
    Ok(())
}

pub fn decrypt_file(password: &str, input_file: &str, output_file: &str) -> std::io::Result<()> {
    // Read the encrypted file content
    let mut input = Vec::new();
    File::open(input_file)?.read_to_end(&mut input)?;
    if input.is_empty() {
        return Ok(());
    }

    // Extract the salt, nonce, and ciphertext
    let (salt, rest) = input.split_at(16);
    let (nonce, ciphertext) = rest.split_at(12);

    // Derive the decryption key
    let key = derive_key(password, salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    // Decrypt the content
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .expect("Decryption failed");

    // Write the plaintext to the output file
    let mut output = File::create(output_file)?;
    output.write_all(&plaintext)?;
    Ok(())
}
