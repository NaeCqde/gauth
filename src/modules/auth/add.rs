use dialoguer::{Input, Password, theme::ColorfulTheme};

use crate::error::AppError;

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
    let entry = keyring::Entry::new("gauth", &name)?;
    Ok(())
}
