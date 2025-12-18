use clap::{Parser, Subcommand};
use dialoguer::Input;
use indicatif::{ProgressBar, ProgressStyle};
use keyring::Entry;
use qr2term::print_qr;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP}; // Secret は不要なので削除
use rand::Rng; // rand::distributions は不要になりました
use rand::distr::Alphanumeric; // 最新の rand 0.9 ではここに変更されました

#[derive(Parser)]
#[command(name = "gauth", version = "1.0", about = "Secure TOTP CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 新規アカウント追加 (セキュア保存 & 回復キー発行)
    Add { 
        name: String,
        #[arg(short, long)]
        qr: bool,
    },
    /// TOTPコード表示 (リアルタイム描画対応)
    Get { 
        name: String,
        #[arg(short, long)]
        watch: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Add { name, qr } => {
            let secret_raw: String = Input::new()
                .with_prompt("Enter Secret Key (Base32)")
                .interact_text()?;

            // 1. 回復キーの生成 (最新の rand 0.9 の書き方)
            println!("\n[IMPORTANT] Recovery Keys (Save these in a safe place):");
            for _ in 0..3 {
                let key: String = rand::rng()
                    .sample_iter(&Alphanumeric)
                    .take(12)
                    .map(char::from)
                    .collect();
                println!("  - {}", key.to_uppercase());
            }

            // 2. セキュア保存
            let entry = Entry::new("gauth-rs", &name)?;
            entry.set_password(&secret_raw.replace(" ", ""))?; // 空白を除去して保存

            // 3. QR表示
            if qr {
                let auth_url = format!("otpauth://totp/{}?secret={}&issuer=gauth", name, secret_raw);
                println!("\nScan this QR code:");
                print_qr(&auth_url).map_err(|_| "Failed to render QR code")?;
            }

            println!("\nAccount '{}' added successfully.", name);
        }

        Commands::Get { name, watch } => {
            let entry = Entry::new("gauth-rs", &name)?;
            let secret_str = entry.get_password()?;
            
            // 最新の base32 と totp-rs の仕様に合わせたデコードと初期化
            let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_str.to_uppercase())
                .ok_or("Invalid Base32 secret")?;

            // TOTP::new は引数が増えているため、デフォルト値を活用
            let totp = TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                secret_bytes,
                None,         // issuer (None)
                name.clone(), // account name
            ).map_err(|e| format!("TOTP Error: {}", e))?;

            if watch {
                render_loop(totp);
            } else {
                println!("Code: {}", totp.generate_current()?);
            }
        }
    }
    Ok(())
}

fn render_loop(totp: TOTP) {
    let pb = ProgressBar::new(30);
    pb.set_style(
        ProgressStyle::with_template("{prefix} [{bar:30}] {msg}s left")
            .unwrap()
            .progress_chars("=>-"),
    );

    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let remaining = 30 - (now % 30);
        let code = totp.generate_current().unwrap();

        pb.set_prefix(format!("Code: \x1b[1;32m{}\x1b[0m", code));
        pb.set_position(remaining);
        pb.set_message(remaining.to_string());

        if remaining == 30 { pb.reset(); }
        sleep(Duration::from_millis(500));
    }
}

