use std::io;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
    widgets::{Block, Borders, Paragraph},
    layout::{Layout, Constraint, Direction},
    Frame,
};
use rpassword::read_password; // rpasswordを追加
use crate::modules::auth; // authモジュールを追加
use crate::modules::auth::AuthEntry; // AuthEntryを追加
use std::time::{Duration, SystemTime, UNIX_EPOCH};


fn draw_ui(f: &mut Frame, entries: &[AuthEntry]) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(100)].as_ref())
        .split(f.size());

    let mut text = vec![];
    text.push(ratatui::text::Line::from("--- Google Authenticator ---"));
    text.push(ratatui::text::Line::from(""));

    if entries.is_empty() {
        text.push(ratatui::text::Line::from("No authenticators added yet."));
        text.push(ratatui::text::Line::from("Add one using 'gauth auth add'"));
    } else {
        let current_timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
                                                .expect("Time went backwards").as_secs();

        for entry in entries {
            let totp_instance = match entry.to_totp() {
                Ok(t) => t,
                Err(e) => {
                    text.push(ratatui::text::Line::from(format!("Error creating TOTP for {}: {}", entry.name, e)));
                    continue;
                }
            };
            let code: String = totp_instance.generate_current().unwrap_or_else(|_| "ERROR".to_string());
            let remaining_seconds = entry.step - (current_timestamp % entry.step);

            text.push(ratatui::text::Line::from(format!("{}: {} ({}s)", entry.name, code, remaining_seconds)));
        }
    }
    text.push(ratatui::text::Line::from(""));
    text.push(ratatui::text::Line::from("Press 'q' to exit."));


    f.render_widget(
        Paragraph::new(text).block(Block::default().title("GAuth").borders(Borders::ALL)),
        chunks[0],
    );
}

pub fn run_ui() -> io::Result<()> {
    // パスワード入力
    println!("Enter master password for UI:");
    let password = match read_password() {
        Ok(p) => p.into_bytes(),
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            return Err(e);
        }
    };

    let entries: Vec<AuthEntry> = match auth::load_auth_entries_encrypted(&password) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error loading authenticators: {}", e);
            return Err(e);
        }
    };


    // ターミナルをセットアップ
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // アプリケーションループ
    loop {
        terminal.draw(|f| draw_ui(f, &entries))?;

        // イベント処理 (ポーリングで非ブロッキングに)
        if crossterm::event::poll(Duration::from_millis(250))? { // 250msごとにポーリング
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    break;
                }
            }
        } else {
            // イベントがなければ何もしない (UIは再描画されるので最新のTOTPが表示される)
        }
    }

    // ターミナルを復元
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}