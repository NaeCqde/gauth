use clap::builder::styling::{AnsiColor, Styles};
use clap::{ColorChoice, Parser, Subcommand};

// 独自のカラースタイルを定義
fn styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Yellow.on_default())
        .usage(AnsiColor::Green.on_default())
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::Green.on_default())
}
#[derive(Parser, Debug)]
#[command(
    name = "gauth",
    version,
    about = "Google Authenticator CLI",
    // ここでスタイルとカラーの強制適用を設定
    styles = styles(),
    color = ColorChoice::Always
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 認証情報の管理 (add, list, del, show)
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// TUI (Ratatui) によるリアルタイム表示モード
    Ui,
}

#[derive(Subcommand, Debug)]
pub enum AuthAction {
    /// 新しいシークレットキーを追加
    Add {
        /// 識別用の名前
        name: Option<String>,
        /// Base32のシークレットキー
        key: Option<String>,
    },
    /// 登録済みの認証一覧を表示
    List,
    /// 指定した認証情報を削除
    Del { name: String },
    /// 特定のキーの現在のコードを表示
    Show { name: String },
}
