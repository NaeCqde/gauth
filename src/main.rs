use clap::{Parser, Subcommand};
// use totp_rs::{TOTP, Secret, Algorithm}; // 未使用なので削除
mod modules; // modulesを宣言
use modules::auth::{self, AuthEntry};
use std::io; // ioを追加
use rpassword::read_password; // rpasswordを追加
use std::path::PathBuf; // PathBufを追加

fn get_password_input(prompt: &str) -> io::Result<Vec<u8>> {
    println!("{}", prompt);
    let pass = read_password()?;
    if pass.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Password cannot be empty."));
    }
    Ok(pass.into_bytes())
}

fn get_master_password(initial_prompt: &str, confirm_prompt: &str) -> io::Result<Vec<u8>> {
    loop {
        println!("{}", initial_prompt);
        let password = read_password()?;
        if password.is_empty() {
            eprintln!("Password cannot be empty. Please try again.");
            continue;
        }

        println!("{}", confirm_prompt);
        let password_confirm = read_password()?;

        if password == password_confirm {
            return Ok(password.into_bytes());
        } else {
            eprintln!("Passwords do not match. Please try again.");
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticator related commands
    Auth(AuthCommands),
    /// TUI for displaying authenticators
    Ui,
}

#[derive(Parser)]
struct AuthCommands {
    #[command(subcommand)]
    command: AuthSubcommands,
}

#[derive(Subcommand)]
enum AuthSubcommands {
    /// Add a new authenticator
    Add {
        name: String,
        #[arg(long)]
        key: String,
    },
    /// List all authenticators
    List,
    /// Delete an authenticator
    Del {
        name: String,
    },
    /// Show a specific authenticator's TOTP
    Show {
        name: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Auth(auth_commands) => match &auth_commands.command {
            AuthSubcommands::Add { name, key } => {
                println!("Adding authenticator: {} with key: {}", name, key);

                let password: Vec<u8>;
                let mut entries: Vec<auth::AuthEntry>;

                let data_file_path = PathBuf::from(modules::auth::DATA_FILE_NAME);

                if data_file_path.exists() {
                    password = match get_password_input("Enter master password to add authenticator:") {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("Error getting password: {}", e);
                            return;
                        }
                    };
                    entries = match auth::load_auth_entries_encrypted(&password) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("Error loading authenticators: {}", e);
                            return;
                        }
                    };
                } else {
                    password = match get_master_password(
                        "No master password set. Please set a new master password:",
                        "Confirm master password:",
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("Error setting master password: {}", e);
                            return;
                        }
                    };
                    entries = Vec::new(); // 初めての追加なので空のVec
                }

                // 重複チェック (nameで)
                if entries.iter().any(|e| e.name == name.clone()) {
                    eprintln!("Authenticator with name '{}' already exists.", name);
                    return;
                }

                let new_entry = AuthEntry {
                    name: name.clone(),
                    secret_base32: key.clone(),
                    issuer: Some("DefaultIssuer".to_string()),
                    account_name: name.clone(),
                    algorithm_str: "SHA1".to_string(),
                    digits: 6,
                    step: 30,
                };

                entries.push(new_entry.clone());

                match auth::save_auth_entries_encrypted(&entries, &password) {
                    Ok(_) => println!("Authenticator '{}' added successfully.", name),
                    Err(e) => {
                        eprintln!("Error saving authenticators: {}", e);
                        return;
                    }
                }

                // 動作確認のため、追加したエントリでTOTPを生成してみる
                match new_entry.to_totp() {
                    Ok(totp) => {
                        let current_totp: String = totp.generate_current().unwrap();
                        println!("Generated TOTP for testing (from saved entry): {}", current_totp);
                    },
                    Err(e) => eprintln!("Error generating TOTP from new entry: {}", e),
                }
            }
            AuthSubcommands::List => {
                println!("Listing authenticators");
                let password = match get_password_input("Enter master password to list authenticators:") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error getting password: {}", e);
                        return;
                    }
                };

                let entries: Vec<auth::AuthEntry> = match auth::load_auth_entries_encrypted(&password) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("Error loading authenticators: {}", e);
                        return;
                    }
                };

                if entries.is_empty() {
                    println!("No authenticators added yet.");
                } else {
                    println!("--- Registered Authenticators ---");
                    for entry in entries {
                        println!("Name: {}", entry.name);
                        println!("  Issuer: {}", entry.issuer.unwrap_or_else(|| "N/A".to_string()));
                        println!("  Account: {}", entry.account_name);
                        println!("  Algorithm: {}", entry.algorithm_str);
                        println!("  Digits: {}", entry.digits);
                        println!("  Step: {}", entry.step);
                        println!("-------------------------------");
                    }
                }
            }
            AuthSubcommands::Del { name } => {
                println!("Deleting authenticator: {}", name);
                let password = match get_password_input("Enter master password to delete authenticator:") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error getting password: {}", e);
                        return;
                    }
                };

                let mut entries = match auth::load_auth_entries_encrypted(&password) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("Error loading authenticators: {}", e);
                        return;
                    }
                };

                let initial_len = entries.len();
                entries.retain(|entry| entry.name != name.clone());

                if entries.len() == initial_len {
                    eprintln!("Authenticator with name '{}' not found.", name);
                    return;
                }

                match auth::save_auth_entries_encrypted(&entries, &password) {
                    Ok(_) => println!("Authenticator '{}' deleted successfully.", name),
                    Err(e) => {
                        eprintln!("Error saving authenticators: {}", e);
                        return;
                    }
                }
            }
            AuthSubcommands::Show { name } => {
                println!("Showing authenticator: {}", name);
                let password = match get_password_input("Enter master password to show authenticator:") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error getting password: {}", e);
                        return;
                    }
                };

                let entries: Vec<auth::AuthEntry> = match auth::load_auth_entries_encrypted(&password) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("Error loading authenticators: {}", e);
                        return;
                    }
                };

                let entry = if let Some(e) = entries.iter().find(|e| e.name == name.clone()) {
                    e.clone()
                } else {
                    eprintln!("Authenticator with name '{}' not found.", name);
                    return;
                };

                // totp_rs::TOTP型はmain.rsでuseされてないので、ここでインポートし直す


                let totp_instance = match entry.to_totp() {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Error creating TOTP instance: {}", e);
                        return;
                    }
                };

                use indicatif::{ProgressBar, ProgressStyle};
                use std::time::{SystemTime, UNIX_EPOCH, Duration};
                use std::thread;

                let bar = ProgressBar::new(entry.step);
                bar.set_style(ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len}s {msg}")
                    .expect("Failed to create ProgressStyle"));

                loop {
                    let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
                                                        .expect("Time went backwards").as_secs();
                    let remaining_seconds = entry.step - (current_timestamp % entry.step);
                    
                    let code: String = totp_instance.generate_current().unwrap(); // TOTPを生成

                    bar.set_position(remaining_seconds);
                    bar.set_message(format!("TOTP: {}", code));
                    
                    if remaining_seconds == 1 {
                        bar.set_position(entry.step);
                        thread::sleep(Duration::from_secs(1));
                    } else {
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        },
        Commands::Ui => {
            println!("Starting UI");
            if let Err(e) = modules::ui::run_ui() {
                eprintln!("Error running UI: {}", e);
            }
        }
    }
}