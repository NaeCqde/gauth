use crate::error::AppError;

pub fn del(name: String) -> Result<(), AppError> {
    println!("Delete secret command received: name={}", name);
    // TODO: Implement actual secret deletion logic
    Ok(())
}
