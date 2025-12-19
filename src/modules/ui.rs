use crate::error::AppError;
use crate::secrets::{self, SecretManager};
use crossterm::{
    event::{self, Event as CrosstermEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Gauge, ListState, Paragraph},
    Terminal,
};
use std::{
    io,
    panic,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use totp_rs::{Algorithm, TOTP};

/// 認証情報の表示用構造体
struct CredentialDisplay {
    name: String,
    totp_code: Option<String>,
    time_until_next_code: u64,
    decrypted_key_bytes: Vec<u8>,
}

/// アプリケーションの状態管理
struct App {
    credentials_display: Vec<CredentialDisplay>,
    list_state: ListState,
    scroll_offset: usize,
}

impl App {
    fn new(master_password: String, secret_manager: SecretManager) -> Result<Self, AppError> {
        let mut credentials_display = Vec::new();
        let all_names = secret_manager.list_credentials();
        for name in all_names {
            if let Some(cred) = secret_manager.get_credential(name) {
                let decrypted_key_bytes = secrets::decrypt_data(
                    master_password.as_bytes(),
                    &cred.ciphertext,
                    &cred.nonce,
                )?;
                credentials_display.push(CredentialDisplay {
                    name: name.clone(),
                    totp_code: None,
                    time_until_next_code: 0,
                    decrypted_key_bytes,
                });
            }
        }

        let mut list_state = ListState::default();
        if !credentials_display.is_empty() {
            list_state.select(Some(0));
        }

        let mut app = App {
            credentials_display,
            list_state,
            scroll_offset: 0,
        };
        app.update_all_totp_codes()?;
        Ok(app)
    }

    /// TOTPコードと残り時間を一括更新
    fn update_all_totp_codes(&mut self) -> Result<(), AppError> {
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::GeneralError(format!("SystemTime error: {}", e)))?
            .as_secs();

        for cred_display in &mut self.credentials_display {
            let totp_instance = TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                cred_display.decrypted_key_bytes.clone(),
            )
            .map_err(|e| AppError::GeneralError(format!("Failed to create TOTP: {}", e)))?;

            cred_display.totp_code = Some(totp_instance.generate_current().map_err(|e| {
                AppError::GeneralError(format!("Failed to generate TOTP code: {}", e))
            })?);
            cred_display.time_until_next_code = 30 - (current_timestamp % 30);
        }
        Ok(())
    }

    fn next(&mut self) {
        if self.credentials_display.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => (i + 1) % self.credentials_display.len(),
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        if self.credentials_display.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.credentials_display.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }
}

/// UIモードのメインエントリポイント
pub fn run_ui_mode() -> Result<(), AppError> {
    // 1. パニックハンドラの設定 (異常終了時にターミナルを復元する)
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
        default_hook(panic_info);
    }));

    // 2. データのロード
    let master_password = secrets::get_master_password()?;
    let secret_manager = SecretManager::load_secrets(&master_password)?;
    let mut app = App::new(master_password, secret_manager)?;

    // 3. ターミナルの準備
    enable_raw_mode()
        .map_err(|e| AppError::GeneralError(format!("Failed to enable raw mode: {}", e)))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|e| AppError::GeneralError(format!("Failed to enter alternate screen: {}", e)))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)
        .map_err(|e| AppError::GeneralError(format!("Failed to create terminal: {}", e)))?;

    const ITEM_HEIGHT: u16 = 5;

    // 4. メインループ
    loop {
        terminal.draw(|f| {
            let full_area = f.area();

            // レイアウト構成
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // ヘッダー
                    Constraint::Min(0),    // メインリスト
                ])
                .split(full_area);

            // ヘッダー描画
            let header = Paragraph::new(Line::from(vec![
                Span::styled(" GAuth ", Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
                Span::styled("Authenticator", Style::default().fg(Color::Gray)),
            ]))
            .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(Color::DarkGray)))
            .alignment(Alignment::Center);
            f.render_widget(header, chunks[0]);

            // コンテンツエリアの余白設定
            let list_area = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(5),
                    Constraint::Percentage(90),
                    Constraint::Percentage(5),
                ])
                .split(chunks[1])[1];

            let displayable_count = (list_area.height / ITEM_HEIGHT) as usize;
            
            // スクロール計算
            if let Some(selected) = app.list_state.selected() {
                if selected < app.scroll_offset {
                    app.scroll_offset = selected;
                } else if selected >= app.scroll_offset + displayable_count {
                    app.scroll_offset = selected - displayable_count + 1;
                }
            }

            let start = app.scroll_offset;
            let end = (start + displayable_count).min(app.credentials_display.len());
            let mut current_y = list_area.y;

            for (idx, cred) in app.credentials_display[start..end].iter().enumerate() {
                let is_selected = app.list_state.selected() == Some(start + idx);
                
                let card_rect = Rect {
                    x: list_area.x,
                    y: current_y,
                    width: list_area.width,
                    height: ITEM_HEIGHT - 1, // カード間に隙間を作る
                };

                // カードの枠線スタイル
                let (bc, bt) = if is_selected {
                    (Color::Blue, BorderType::Thick)
                } else {
                    (Color::DarkGray, BorderType::Rounded)
                };

                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(bc))
                    .border_type(bt);
                
                f.render_widget(block.clone(), card_rect);
                let inner = block.inner(card_rect);

                // カード内部レイアウト
                let internal = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Min(20),   // 名前とコード
                        Constraint::Length(15), // ゲージ
                    ])
                    .split(inner);

                // 左側: テキスト情報
                let info_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(1), Constraint::Length(1)])
                    .split(internal[0]);

                f.render_widget(
                    Paragraph::new(Span::styled(&cred.name, Style::default().fg(if is_selected { Color::White } else { Color::Gray }))),
                    info_chunks[0]
                );

                let code_raw = cred.totp_code.clone().unwrap_or_else(|| "------".into());
                let code_disp = if code_raw.len() == 6 {
                    format!("{} {}", &code_raw[0..3], &code_raw[3..6])
                } else {
                    code_raw
                };

                let color = if cred.time_until_next_code <= 5 { Color::Red } else { Color::Blue };
                f.render_widget(
                    Paragraph::new(Span::styled(code_disp, Style::default().fg(color).add_modifier(Modifier::BOLD))),
                    info_chunks[1]
                );

                // 右側: タイムゲージ
                let gauge = Gauge::default()
                    .gauge_style(Style::default().fg(color).bg(Color::Rgb(30, 30, 30)))
                    .ratio(cred.time_until_next_code as f64 / 30.0)
                    .label(format!("{}s", cred.time_until_next_code))
                    .use_unicode(true);

                let gauge_area = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(1), Constraint::Length(1)])
                    .split(internal[1])[1]; // 2行目に配置して中央寄せっぽくする

                f.render_widget(gauge, gauge_area);

                current_y += ITEM_HEIGHT;
            }
        })
        .map_err(|e| AppError::GeneralError(format!("Draw error: {}", e)))?;

        // 入力イベント
        if event::poll(Duration::from_millis(100))? {
            if let CrosstermEvent::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up | KeyCode::Char('k') => app.previous(),
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    _ => {}
                }
            }
        }

        // 時間による自動更新
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if let Some(first) = app.credentials_display.first() {
            if (30 - (now % 30)) != first.time_until_next_code {
                app.update_all_totp_codes()?;
            }
        }
    }

    // 5. 正常終了時の復元
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
