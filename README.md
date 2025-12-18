# G Auth

Google AuthenticatorのCLI版のようなもの

## コマンドライン
gauth
 - auth
  - add(name:Option<String>, key:Option<String>)
    base32でシークレットキーを入力させる。
    自動でキーリング、対応していなければ手動で暗号化(パスワード入力をさせる)
    そして登録する
  - list
    登録済みの認証を表示する。
  - del(name:String)
    認証を削除する
  - show (name:String)
    一行に、対象のキーを表示する。indicatifを使おう。
 - ui
   ratatuiでUIを表示する。
   リアルタイムで登録済みの全てのキーの名前、6桁のキー、残り時間を描画する。

   