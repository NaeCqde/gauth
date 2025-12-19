use crate::error::AppError;

pub fn del(name: String) -> Result<(), AppError> {
    let entry = keyring::Entry::new("gauth", &name)?;
    entry.delete_credential()?;
    Ok(())
}
