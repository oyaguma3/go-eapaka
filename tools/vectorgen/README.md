# vectorgen: 外部実装からテストベクタを作る

go-eapaka のテストで使うベクタ（`testdata/vectors/*.json`）を、go-eapaka とは別の実装から生成します。

go-eapaka はテストツールと RADIUS サーバの両方から使われることがあります。その場合、ライブラリに誤りがあっても両者で同じように間違えるので、テストで見つかりません。そこで、hostap（hostapd / wpa_supplicant）と Python の標準ライブラリで作った値と一致することを確かめます。

生成したベクタはリポジトリにコミットしてあるので、`go test ./...` を実行するだけならこのディレクトリの手順は不要です。

## 必要なもの

- C コンパイラ（`cc`）、`make`、`git`
- Python 3（標準ライブラリだけを使います）
- OpenSSL は不要です。暗号処理には hostap 内蔵の実装（`sha1-internal.c`、`aes-internal*.c` など）を使います。

## 使い方

```sh
cd tools/vectorgen
make vectors   # hostap を取得・ビルドし、testdata/vectors/*.json を生成し直す
make check     # 生成し直した結果が、コミット済みのベクタと一致することを確かめる
```

| ターゲット | 内容 |
|---|---|
| `fetch` | hostap を `_build/hostap` に clone し、タグが指すコミットを確認する |
| `build` | `_build/vectorgen` と `_build/mppecheck` をビルドする |
| `vectors` | ベクタを生成し直す（既定のターゲット） |
| `check` | `vectors` のあと `git diff --exit-code` で差分がないことを確かめる |
| `clean` / `distclean` | ビルド結果を消す / `_build` ごと消す |

`_build` は先頭が `_` なので、go のパッケージパターン（`./...`）の対象外です。`go vet` や `go test` には影響しません。

## hostap のバージョン

`Makefile` の `HOSTAP_TAG` と `HOSTAP_COMMIT` で固定しています。

- タグ: `hostap_2_12`
- コミット: `831364bf02710ad09c2f27d3efa92abeeb5634c0`

上げるときは両方を書き換えて `make distclean vectors` を実行し、ベクタの差分を確認します。各 JSON の `source` にもバージョンが入るので、値が変わらなくても `source` は変わります。

## 生成するファイル

| ファイル | 生成元 | 内容 |
|---|---|---|
| `aka_keys.json` | hostap `eap_aka_derive_mk`、`eap_sim_derive_keys` | EAP-AKA のフル認証の MK・K_encr・K_aut・MSK・EMSK（RFC 4187 §7） |
| `aka_prime_keys.json` | hostap `eap_aka_prime_derive_ck_ik_prime`、`eap_aka_prime_derive_keys` | EAP-AKA' の CK'・IK' とフル認証の鍵（RFC 9048 §3.3） |
| `reauth_keys_aka.json` | hostap `eap_sim_derive_keys_reauth` | EAP-AKA の再認証の MSK・EMSK。中間値の XKEY' も含む（RFC 4187 §7） |
| `reauth_keys_aka_prime.json` | hostap `eap_aka_prime_derive_keys_reauth` | EAP-AKA' の再認証の MSK・EMSK（RFC 9048 §3.3） |
| `encr_data.json` | hostap `eap_sim_msg_add_encr_start` / `_end`、`eap_sim_parse_encr` | AT_ENCR_DATA の平文と暗号文。AT_PADDING が 0・4・8・12 バイトのケースを含む（RFC 4187 §10.12） |
| `packets.json` | hostap `eap_sim_msg_*`、`eap_sim_add_mac(_sha256)`、`eap_sim_verify_mac(_sha256)` | AT_IV・AT_ENCR_DATA・AT_MAC を含む完成したパケット。再認証の応答の MAC は NONCE_S を追加データにして計算する（RFC 4187 §9.8） |
| `packets_bidding_violation.json` | hostap `eap_sim_msg_*`、`eap_sim_add_mac_sha256`、`eap_sim_verify_mac_sha256` | RFC 9048 §4 に違反する、AT_BIDDING を含む EAP-AKA' のパケット。`ParseOptions.AllowBiddingInAKAPrime` で読み込んで MAC を検証するテストのために、意図的に作る。既定の `Parse` で読むテストに混ざらないよう、`packets.json` とは別のファイルにしている |
| `packets_reserved_nonzero.json` | hostap `eap_sim_msg_*`、`aes_128_cbc_encrypt`、`eap_sim_add_mac(_sha256)`、`eap_sim_verify_mac(_sha256)`、`eap_sim_parse_encr` | AT_RAND・AT_AUTN・AT_RESULT_IND・AT_IV・AT_ENCR_DATA の Reserved を意図的に 0 以外にしたパケット。受信したバイト列のまま MAC を検証する `VerifyMacRaw` のテストに使う。AT_MAC 自身の Reserved は 0 |
| `mppe.json` | Python `hashlib.md5`（hostap `radius.c` で照合） | MS-MPPE-Send/Recv-Key の暗号化（RFC 2548 §2.4.2） |
| `checkcode.json` | Python `hashlib.sha1` / `sha256` | AT_CHECKCODE（RFC 4187 §10.13、RFC 9048 §3.4.3） |

## 生成の仕組み

### C の生成器（`vectorgen.c`）

hostap の `src/eap_common/eap_sim_common.c` と内蔵の暗号実装にリンクし、hostap の関数を呼んで値を作ります。

- **IV の固定**: `eap_sim_msg_add_encr_start()` は `random_get_bytes()` で AT_IV を作ります。結果を再現できるよう、`random.c` はリンクせず、`vectorgen.c` で `random_get_bytes()` を定義して指定した IV を返します。IV の使い回しを防ぐため、指定した IV は 1 回で無効になります。
- **自己検証**: 書き出す前に次を確かめ、失敗したら何も書き出さずに終了します。
  - RFC 9048 付録 D のケース 1 と一致すること（リンクした hostap と暗号実装が正しく動いていることの確認）
  - 組み立てたパケットの MAC を hostap の `eap_sim_verify_mac(_sha256)` で検証できること。追加データを使うケースでは、追加データなしの検証が失敗すること
  - AT_ENCR_DATA を hostap の `eap_sim_parse_encr()` で復号・解析できること
  - `encr_data.json` に AT_PADDING が 0・4・8・12 バイトのケースがそろっていること
- **入力値**: 入力はすべて `vectorgen.c` に固定値で書いてあります。RFC 9048 付録 D の値、64 バイトを超える ID（ハッシュの複数ブロックを通す）、counter の境界値（1、2、0xFFFF）などを含みます。`packets.json` の鍵は、`aka_keys.json` と `aka_prime_keys.json` の最初のケースで導出したものです。

### Python の生成器（`pyvectors.py`）

- **MPPE 鍵**: RFC 2548 §2.4.2 の手順を `hashlib.md5` で実装しています。`make vectors` では、各ケースを `mppecheck`（hostap の `radius.c` の `encrypt_ms_key` / `decrypt_ms_key` を呼ぶ小さなプログラム）でも照合し、一致しなければ書き出しません。
- **AT_CHECKCODE**: AKA-Identity の Request と Response を組み立て、そのハッシュを計算します。ハッシュの対象は、EAP パケット全体（EAP ヘッダを含む）を送受信した順に区切りなしでつないだものです。hostap の `eap_aka.c`（ピア側・サーバ側の `id_msgs`）と同じ扱いです。AKA-Identity をやり取りしていなければ値は空（長さ 0）です。

## JSON の形式

```json
{
  "source": "生成に使った実装と関数",
  "generator": "生成したプログラム",
  "cases": [
    { "name": "ケース名", "...": "..." }
  ]
}
```

- バイト列は小文字の 16 進文字列です。値がないときは空文字列です。
- ID などの文字列はそのまま、counter などの整数は数値で書きます。
- 各ファイルのメンバーは、Go の `vectors_test.go` の型定義（`akaKeysVector` など）とコメントを参照してください。

## Go のテストから使う

`vectors_test.go` の `loadVectors` で読み込みます。`encoding/json/v2` を使い、想定外のメンバーがあれば失敗します（`json.RejectUnknownMembers`）。16 進文字列は `hexBytes` 型で `[]byte` に変換されます。

```go
for _, v := range loadVectors[reauthAKAVector](t, "reauth_keys_aka.json") {
	t.Run(v.Name, func(t *testing.T) {
		// v.Identity, v.Counter, v.NonceS, v.MK, v.MSK, v.EMSK を使う
	})
}
```

## ライセンス

hostap は BSD ライセンスです。このリポジトリには hostap のソースを含めず、`make fetch` で取得します。
