use clap::Parser;
use gauth::{args, auth, ui};

fn main() {
    let args = args::Args::parse();

    match args.command {
        args::Commands::Auth { action } => {
            match action {
                args::AuthAction::Add { name, key } => {
                    auth::add(name, key);
                }
                args::AuthAction::List => {
                    auth::list();
                }
                args::AuthAction::Del { name } => {
                    auth::del(name);
                }
                args::AuthAction::Show { name } => {
                    auth::show(name);
                }
            }
        }
        args::Commands::Ui => {
            ui::run_ui_mode();
        }
    }
}