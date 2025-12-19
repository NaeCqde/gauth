use dialoguer::{Input, Password, theme::ColorfulTheme};

use crate::error::AppError;
use crate::secrets::{self, SecretManager};

pub fn add(name: Option<String>, key: Option<String>) -> Result<(), AppError> {
    let name = match name {
        Some(name) => name,
        None => Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Name")
            .interact_text()
            .unwrap(),
    };
    let key = match key {
        Some(key) => key,
        None => Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Key")
            .interact()
            .unwrap(),
    };
    // -- add.rs --
    let key = key.trim().replace(" ", "").to_uppercase(); // 大文字に統一
    let bin = base32::decode(
        base32::Alphabet::Rfc4648 { padding: true }, // 標準的な設定（padding: trueで両方対応可）
        &key,
    )
    .ok_or(AppError::InvalidKey)?;

    let master_password = secrets::get_master_password()?;
    let master_password_bytes = master_password.as_bytes();

    let (ciphertext, nonce) = secrets::encrypt_data(master_password_bytes, &bin)?;

    let mut secret_manager = SecretManager::load_secrets(&master_password)?;
    secret_manager.add_credential(name.clone(), ciphertext, nonce);
    secret_manager.save_secrets(&master_password)?;

    println!("Successfully added auth: {}", name);
    Ok(())
}
