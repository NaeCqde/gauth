use crate::error::AppError;
use crate::secrets::{self, SecretManager};

pub fn show(name: String) -> Result<(), AppError> {
    let master_password = secrets::get_master_password()?;
    let master_password_bytes = master_password.as_bytes();

    let secret_manager = SecretManager::load_secrets(&master_password)?;
    
    match secret_manager.get_credential(&name) {
        Some(credential) => {
            let plaintext_bytes = secrets::decrypt_data(
                master_password_bytes,
                &credential.ciphertext,
                &credential.nonce,
            )?;
            let key = base32::encode(base32::Alphabet::Rfc4648Lower { padding: true }, &plaintext_bytes);
            println!("Key for {}: {}", name, key);
        }
        None => {
            println!("Auth '{}' not found.", name);
        }
    }

    Ok(())
}
