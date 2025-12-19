use crate::error::AppError;
use crate::secrets::{self, SecretManager};
use indicatif::{ProgressBar, ProgressStyle};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};

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
            let b32_key = base32::encode(
                base32::Alphabet::Rfc4648 { padding: true },
                &plaintext_bytes,
            );

            let totp_instance = TOTP::new(Algorithm::SHA1, 6, 1, 30, b32_key.clone().into())
                .map_err(|e| AppError::GeneralError(format!("Failed to create TOTP: {}", e)))?;

            loop {
                let current_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| AppError::GeneralError(format!("SystemTime error: {}", e)))?
                    .as_secs();
                let time_until_next_code = 30 - (current_timestamp % 30);

                let code = totp_instance.generate_current().map_err(|e| {
                    AppError::GeneralError(format!("Failed to generate TOTP code: {}", e))
                })?;

                let pb = ProgressBar::new(30);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template("{msg} [{eta_precise}] {bar:40.cyan/blue}")
                        .unwrap()
                        .progress_chars("##-"),
                );
                pb.set_message(format!("TOTP Code for {}: {}", name, code));

                for _ in 0..time_until_next_code {
                    pb.inc(1);
                    thread::sleep(Duration::from_secs(1));
                }
                pb.finish_and_clear();
            }
        }
        None => {
            println!("Auth '{}' not found.", name);
        }
    }

    Ok(())
}
