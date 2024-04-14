use wasm_bindgen::prelude::*;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, SaltString},
    Argon2, PasswordVerifier,
};

#[wasm_bindgen]
pub fn hash(password: &str, salt: &[u8]) -> String {
    let parsed_salt = SaltString::encode_b64(salt).unwrap();
    return Argon2::default()
        .hash_password(password.as_bytes(), &parsed_salt)
        .unwrap()
        .to_string();
}

#[wasm_bindgen]
pub fn verify(password: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).unwrap();
    return Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();
}
