use crate::error::AppError;
use crate::secrets::{self, SecretManager};

pub fn del(name: String) -> Result<(), AppError> {
    let master_password = secrets::get_master_password()?;

    let mut secret_manager = SecretManager::load_secrets(&master_password)?;
    if secret_manager.delete_credential(&name).is_some() {
        secret_manager.save_secrets(&master_password)?;
        println!("Successfully deleted auth: {}", name);
    } else {
        println!("Auth '{}' not found.", name);
    }

    Ok(())
}
