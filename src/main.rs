use clap::Parser;
use gauth::{command, auth, ui};

fn main() {
    let args = command::Args::parse();

    match args.command {
        command::Commands::Auth { action } => {
            match action {
                command::AuthAction::Add { name, key } => {
                    auth::add_secret(name, key);
                }
                command::AuthAction::List => {
                    auth::list_secrets();
                }
                command::AuthAction::Del { name } => {
                    auth::delete_secret(name);
                }
                command::AuthAction::Show { name } => {
                    auth::show_code(name);
                }
            }
        }
        command::Commands::Ui => {
            ui::run_ui_mode();
        }
    }
}