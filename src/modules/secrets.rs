use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use dialoguer::{Password, theme::ColorfulTheme};
use keyring::Entry;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credential {
    pub name: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SecretManager {
    credentials: HashMap<String, Credential>,
}

impl SecretManager {
    pub fn new() -> Self {
        SecretManager::default()
    }

    pub fn load_secrets(master_password: &str) -> Result<Self, super::error::AppError> {
        let path = get_config_file_path()?;
        if !path.exists() {
            return Ok(SecretManager::new());
        }

        let mut file = File::open(&path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        // 暗号化されたTOMLデータを復号化
        let key_bytes = master_password.as_bytes();
        // nonceは12バイトと定義されているので、最後の12バイトをnonceとする
        if contents.len() < 12 {
            return Err(super::error::AppError::DecryptionError);
        }
        let (encrypted_toml, stored_nonce) = contents.split_at(contents.len() - 12);

        let decrypted_toml_bytes = decrypt_data(key_bytes, encrypted_toml, stored_nonce)?;
        let decrypted_toml_str = String::from_utf8(decrypted_toml_bytes)
            .map_err(|_| super::error::AppError::DecryptionError)?;

        let manager: SecretManager = toml::from_str(&decrypted_toml_str)?;
        Ok(manager)
    }

    pub fn save_secrets(&self, master_password: &str) -> Result<(), super::error::AppError> {
        let path = get_config_file_path()?;
        let parent_dir = path
            .parent()
            .ok_or(super::error::AppError::ConfigDirNotFound)?;
        fs::create_dir_all(parent_dir)?;

        let toml_string = toml::to_string(&self)?;

        // TOMLデータを暗号化
        let key_bytes = master_password.as_bytes();
        let (ciphertext, nonce) = encrypt_data(key_bytes, toml_string.as_bytes())?;

        let mut file = File::create(&path)?;
        file.write_all(&ciphertext)?;
        file.write_all(&nonce)?; // nonceを暗号文の末尾に追加

        Ok(())
    }

    pub fn add_credential(&mut self, name: String, ciphertext: Vec<u8>, nonce: Vec<u8>) {
        self.credentials.insert(
            name.clone(),
            Credential {
                name,
                ciphertext,
                nonce,
            },
        );
    }

    pub fn get_credential(&self, name: &str) -> Option<&Credential> {
        self.credentials.get(name)
    }

    pub fn delete_credential(&mut self, name: &str) -> Option<Credential> {
        self.credentials.remove(name)
    }

    pub fn list_credentials(&self) -> Vec<&String> {
        self.credentials.keys().collect()
    }
}

pub fn get_config_file_path() -> Result<PathBuf, super::error::AppError> {
    let mut path = dirs::config_dir().ok_or(super::error::AppError::ConfigDirNotFound)?;
    path.push("gauth");
    path.push("credentials.toml");
    Ok(path)
}

pub fn get_master_password() -> Result<String, super::error::AppError> {
    const SERVICE_NAME: &str = "gauth_master_password";
    let entry = Entry::new(SERVICE_NAME, "gauth_user")?;

    match entry.get_secret() {
        Ok(password_bytes) => {
            let password = String::from_utf8(password_bytes)
                .map_err(|_| super::error::AppError::DecryptionError)?;
            Ok(password)
        }
        Err(keyring::Error::NoEntry) => {
            println!("Master password not found. Please set one up.");
            let password = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Master Password")
                .interact()?;
            let password_confirm = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Confirm Master Password")
                .interact()?;

            if password != password_confirm {
                return Err(super::error::AppError::MasterPasswordMismatch);
            }
            entry.set_secret(password.as_bytes())?;
            Ok(password)
        }
        Err(e) => Err(e.into()), // #[from] keyring::Error
    }
}

pub fn encrypt_data(
    master_key_material: &[u8],
    data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), super::error::AppError> {
    let mut hasher = Sha256::new();
    hasher.update(master_key_material);
    let key_bytes = hasher.finalize();

    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| super::error::AppError::EncryptionError)?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt_data(
    master_key_material: &[u8],
    ciphertext: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, super::error::AppError> {
    let mut hasher = Sha256::new();
    hasher.update(master_key_material);
    let key_bytes = hasher.finalize();

    let key = Key::<Aes256Gcm>::from_slice(key_bytes.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| super::error::AppError::DecryptionError)?;
    Ok(plaintext)
}
