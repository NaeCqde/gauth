use crate::error::AppError;
use crate::secrets::{self, SecretManager};

pub fn list() -> Result<(), AppError> {
    let master_password = secrets::get_master_password()?;
    let secret_manager = SecretManager::load_secrets(&master_password)?;

    let credentials = secret_manager.list_credentials();

    if credentials.is_empty() {
        println!("No credentials found.");
    } else {
        println!("Available credentials:");
        for name in credentials {
            println!("  - {}", name);
        }
    }

    Ok(())
}
