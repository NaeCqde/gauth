use serde::{Serialize, Deserialize};
use totp_rs::{Secret, Algorithm};
use std::{fs, io};
use std::path::PathBuf;
use serde_json;

use aes_gcm::{
    aead::{Aead, KeyInit}, // OsRngを削除
    Aes256Gcm, Nonce
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand_core::OsRng;
use rand_core::RngCore;

pub const DATA_FILE_NAME: &str = "gauth_data.json";
const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthEntry {
    pub name: String,
    pub secret_base32: String,
    pub issuer: Option<String>,
    pub account_name: String,
    pub algorithm_str: String,
    pub digits: usize,
    pub step: u64,
}

impl AuthEntry {
    pub fn to_totp(&self) -> Result<totp_rs::TOTP, String> {
        let secret_bytes = match Secret::Encoded(self.secret_base32.clone()).to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => return Err(format!("Error decoding base32 key: {}", e)),
        };

        let algorithm = match self.algorithm_str.as_str() {
            "SHA1" => Algorithm::SHA1,
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            _ => return Err(format!("Unsupported algorithm: {}", self.algorithm_str)),
        };

        Ok(totp_rs::TOTP::new(
            algorithm,
            self.digits,
            1,
            self.step,
            secret_bytes,
            self.issuer.clone(),
            self.account_name.clone(),
        ).expect("Failed to create TOTP instance"))
    }
}


#[derive(Debug, Serialize, Deserialize)]
struct EncryptedData {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    cipher_text: Vec<u8>,
}

pub fn save_auth_entries_encrypted(entries: &[AuthEntry], password: &[u8]) -> io::Result<()> {
    let mut salt = vec![0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let mut key_bytes = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut key_bytes);
    
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "AES-GCM key error"))?;

    let mut nonce_bytes = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plain_text = serde_json::to_vec(entries)?;

    let cipher_text = cipher.encrypt(nonce, plain_text.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

    let encrypted_data = EncryptedData {
        salt,
        nonce: nonce_bytes,
        cipher_text,
    };

    let encrypted_json = serde_json::to_string_pretty(&encrypted_data)?;
    fs::write(DATA_FILE_NAME, encrypted_json)?;
    Ok(())
}

pub fn load_auth_entries_encrypted(password: &[u8]) -> io::Result<Vec<AuthEntry>> {
    let path = PathBuf::from(DATA_FILE_NAME);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let encrypted_json = fs::read_to_string(path)?;
    let encrypted_data: EncryptedData = serde_json::from_str(&encrypted_json)?;

    let mut key_bytes = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password, &encrypted_data.salt, PBKDF2_ITERATIONS, &mut key_bytes);
    
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "AES-GCM key error"))?;
    let nonce = Nonce::from_slice(&encrypted_data.nonce);

    let plain_text = cipher.decrypt(nonce, encrypted_data.cipher_text.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Decryption failed. Incorrect password or corrupted data."))?;

    let entries: Vec<AuthEntry> = serde_json::from_slice(&plain_text)?;
    Ok(entries)
}
