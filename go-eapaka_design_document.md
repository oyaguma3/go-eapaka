# go-eapaka: Design Document

## 1. プロジェクト概要 (Overview)

`go-eapaka` は、**EAP-AKA (RFC 4187)** および **EAP-AKA' (RFC 9048。RFC 5448 を廃止)** プロトコルを扱うための Go 言語用ライブラリです。

RADIUSサーバーや通信テストツールの開発において、EAPパケットの **生成 (Marshal)** と **解析 (Unmarshal)** の双方を厳密かつ容易に行うことを目的としています。

### 設計思想

- **Zero External Dependencies:** プロダクションコードは標準ライブラリ（`encoding/binary`, `crypto/*`）のみで構成し、高い移植性と保守性を確保する。
- **RFC Compliance:** RFC 3748 (EAP), RFC 4187 (EAP-AKA), RFC 9048 (EAP-AKA') に準拠し、エッジケース（EAP-Success/Failureなど）も正しく扱う。
- **Security First:** MAC計算時のゼロ埋め処理や、タイミング攻撃対策（定数時間比較）をライブラリ内部に隠蔽する。
- **Developer Friendly:** `go-cmp` を活用した堅牢なテストと、GoDoc で閲覧しやすいドキュメント構造を提供する。
- **Independent Test Vectors:** 本ライブラリはテストツールと RADIUS サーバの両方から使われうるため、ライブラリの誤りが両者で一致して見逃されないよう、暗号処理は独立した実装（hostap、Python）から生成したテストベクタで検証する（§5.3）。
- **Peer / Server Symmetry:** ピア側からもサーバ側からも使えるよう、暗号化と復号、MAC の計算と検証を対で提供する。

## 2. パッケージ構成 (Package Structure)

単一責任の原則に基づき、以下のファイル構成を採用します。パッケージレベルのドキュメントは `doc.go` に集約します。

```
go-eapaka/
├── doc.go                # package eapaka の概要、全体的な使用例
├── packet.go             # Packet構造体
├── packet_marshal.go     # Marshal (Packet -> []byte)
├── packet_unmarshal.go   # Parse / ParseWithOptions / ParseAttributes ([]byte -> Packet, []Attribute)
├── attributes.go         # Attributeインターフェース, 個別の構造体 (AT_RAND等)
├── attributes_decoder.go # Attribute解析用のファクトリー関数
├── notification.go       # AT_NOTIFICATION のコード値の定数と変換 (FullCode, NewNotification)
├── encr_data.go          # AT_ENCR_DATA の暗号化・復号 (EncryptAttributes, DecryptAttributes, NewIV)
├── crypto.go             # MAC (HMAC-SHA1/256) 計算・検証ロジック（追加データ付きを含む）
├── kdf.go                # 鍵導出（フル認証・再認証）と PRF
├── kdf_negotiation.go    # AT_KDF の交渉の補助
├── checkcode.go          # AT_CHECKCODE の計算 (ComputeCheckcode)
├── exported_params.go    # Session-Id, Peer-Id, Server-Id
├── mppe.go               # MS-MPPE-Send/Recv-Key の暗号化・復号
├── identity_5g.go        # 5G のネットワーク名・ID の判定
├── sha1_compress.go      # FIPS 186-2 PRF 用の SHA-1 圧縮関数
├── types.go              # 型定義 (EAPCode, AttributeType等), IsSkippable
├── *_test.go             # go-cmpを用いたテスト、外部ベクタとの照合、Exampleコード
├── testdata/vectors/     # 外部実装から生成したテストベクタ (JSON)
└── tools/vectorgen/      # テストベクタの生成プログラム（C・Python。Go のビルド対象外）
```

## 3. データ構造 (Data Structures)

GoDocにおいて「各フィールドがRFCのどこに基づいているか」が即座に分かるよう、コメント規約を定めます。

### 3.1 Packet 構造体

EAPパケット全体を表現します。

```go
// Packet represents an EAP packet including EAP-AKA/AKA' specific data.
// It supports both EAP-Request/Response (with attributes) and EAP-Success/Failure (header only).
type Packet struct {
    // Code indicates the EAP Code (e.g., Request, Response).
    // See RFC 3748 Section 4.
    Code uint8

    // Identifier handles request/response matching.
    Identifier uint8

    // Type indicates the EAP Method Type.
    // Use TypeAKA (23) or TypeAKAPrime (50).
    // This field is ignored if Code is Success(3) or Failure(4).
    Type uint8

    // Subtype indicates the EAP-AKA Subtype (e.g., Challenge, Synchronization-Failure).
    // See RFC 4187 Section 11.
    Subtype uint8

    // Attributes contains the list of EAP-AKA attributes.
    Attributes []Attribute
}
```

### 3.2 Attribute インターフェース

全ての EAP-AKA 属性は `Attribute` インターフェースを実装し、TLV構造やパディング処理を隠蔽します。

```go
// Attribute is the interface implemented by all EAP-AKA attributes.
type Attribute interface {
    // Type returns the attribute type (e.g., AT_RAND).
    Type() AttributeType
    
    // Marshal serializes the attribute into a byte slice, including padding.
    Marshal() ([]byte, error)
    
    // Unmarshal parses the value part of the attribute.
    Unmarshal(data []byte) error
}
```

### 3.3 実装済み Attribute 構造体

RFC 4187 および RFC 9048 で定義される以下の属性を実装しています。

- **認証・鍵生成関連:** `AT_RAND`, `AT_AUTN`, `AT_RES`, `AT_AUTS`, `AT_MAC`
- **ID要求・応答:** `AT_PERMANENT_ID_REQ`, `AT_ANY_ID_REQ`, `AT_FULLAUTH_ID_REQ`, `AT_IDENTITY`
- **通知・エラー:** `AT_NOTIFICATION`, `AT_CLIENT_ERROR_CODE`
- **再認証・仮名:** `AT_NEXT_PSEUDONYM`, `AT_NEXT_REAUTH_ID`, `AT_COUNTER`, `AT_COUNTER_TOO_SMALL`, `AT_NONCE_S`
- **暗号化:** `AT_IV`, `AT_ENCR_DATA`, `AT_PADDING`
- **EAP-AKA' 拡張:** `AT_KDF`, `AT_KDF_INPUT`, `AT_BIDDING` (flags: `AtBiddingFlagAKAPrime`)
- **その他:** `AT_CHECKCODE`, `AT_RESULT_IND`, `AT_NONCE_MT`, `AT_VERSION_LIST`, `AT_SELECTED_VERSION`

未知の属性は `GenericAttribute` として保持します。`IsSkippable` で、スキップ可能（128〜255）かどうかを判定できます（RFC 4187 Section 8.1）。

属性の構造体に関する補足:

- **AT_NOTIFICATION:** `AtNotification` は S ビット（0x8000）・P ビット（0x4000）と、下位 14 bit の `Code` を別々のフィールドで持つ。RFC 4187 Section 10.19 の 16 bit のコード値（`NotificationSuccess` などの定数）とは、`FullCode` と `NewNotification` で変換する。RFC 4187 Section 11 には P ビットの意味が Section 6.1・10.19 と逆に読める記述があるが、Section 6.1・10.19 の定義（P = 0 は認証成功後だけ、P = 1 は認証前だけ）に従う。
- **AT_ENCR_DATA:** `AtEncrData` は暗号文をそのまま持つ。入れ子の属性の暗号化・復号は `EncryptAttributes` / `DecryptAttributes` で行う（§4.5）。
- **AT_CHECKCODE:** `AtCheckcode` は値を持つだけで、計算は `ComputeCheckcode` で行う（§4.7）。

### 3.4 鍵の構造体

```go
// EAP-AKA（RFC 4187 Section 7）
type AkaKeys struct {
    K_encr []byte // 16 バイト
    K_aut  []byte // 16 バイト
    MSK    []byte // 64 バイト
    EMSK   []byte // 64 バイト
    MK     []byte // 20 バイト。再認証の鍵導出に使う（v0.2.0 で末尾に追加）
}

// EAP-AKA'（RFC 9048 Section 3.3）
type AkaPrimeKeys struct {
    K_encr []byte // 16 バイト
    K_aut  []byte // 32 バイト
    K_re   []byte // 32 バイト。再認証の鍵導出に使う
    MSK    []byte // 64 バイト
    EMSK   []byte // 64 バイト
}

// 高速再認証（K_encr と K_aut はフル認証のものを使い続ける）
type ReauthKeys struct {
    MSK  []byte // 64 バイト
    EMSK []byte // 64 バイト
}
```

`AkaKeys` にフィールドを追加したため、フィールド名を書かない複合リテラルはコンパイルできなくなる。フィールド名を書いたリテラルや `DeriveKeysAKA` の戻り値を使うコードには影響しない。

### 3.5 解析オプション

```go
// ParseOptions のゼロ値は Parse と同じ動作になる。
type ParseOptions struct {
    // EAP-AKA' のパケットに含まれる AT_BIDDING を受け付ける（RFC 9048 Section 4 違反）。
    // テストツールが、テスト対象の違反を報告するために使う。
    AllowBiddingInAKAPrime bool
}
```

## 4. 処理ロジック詳細 (Logic Details)

### 4.1 Unmarshal (Parse) フロー

RFC 3748 および RFC 4187 に従い、以下の順序で検証を行います。

1. **EAP Header Check:** 最低4バイト（Code, ID, Length）を確認。
2. **Code Check:**
    - **Success(3) / Failure(4):** ペイロードを持たないため、属性解析を行わず即座に `Packet` を返却。
    - **Request(1) / Response(2):** ステップ3へ進む。
3. **Type Check:** Type が 23 (AKA) または 50 (AKA') であるか確認。それ以外の場合は属性解析を行わない。
4. **AKA Header Check:** Subtypeを取得し、Reserved領域をスキップ。
5. **Attribute Parsing:** バイト列の末尾までループし、`decodeAttribute` ファクトリー関数を使用して構造体にマッピング。
    - Type が 50 (AKA') のパケットに `AT_BIDDING` があればエラーにする（RFC 9048 Section 4）。`ParseWithOptions` で `AllowBiddingInAKAPrime` を指定したときは受け付ける。
    - 属性の並びの解析は `ParseAttributes`（AT_ENCR_DATA の復号結果など、EAP パケットに包まれていない属性の並び）と共通の処理で行う。

`Parse` は `ParseWithOptions` をゼロ値の `ParseOptions` で呼ぶ。

### 4.2 Marshal (Construction) フロー

- **Length Calculation:** パケット全体の Length、各属性の Length（4バイトワード単位）を自動計算。
- **Padding:** EAP-AKAの仕様に従い、各属性が **4バイト境界（32-bit boundary）** に整合するよう、末尾に `0x00` パディングを自動付与。
- **AT_BIDDING:** Type が 50 (AKA') のパケットに `AT_BIDDING` があればエラーにする。ただし MAC の計算・検証（§4.4）では、`ParseWithOptions` で読み込んだ違反パケットも扱えるよう、この検査をしない内部関数で組み立てる。

### 4.3 属性単位のRFC準拠ルール (Attribute-Level Compliance Rules)

相互接続性の観点で重要な属性については、以下の制約を実装で強制します。

- **AT_RAND / AT_AUTN (RFC 4187):**
  - Value形式は `Reserved(2) + RAND/AUTN(16)` を厳守する。
  - Marshal/Unmarshal ともに Reserved領域を先頭として扱う。
- **AT_PADDING (RFC 4187 Section 10.12):**
  - Value長は `2` / `6` / `10` バイトのみ許容（属性全体長では `4` / `8` / `12`）。
  - Unmarshal時は全バイト `0x00` を検証する。
- **AT_CHECKCODE (RFC 4187 / RFC 9048):**
  - Checkcode長は `0` / `20` (AKA) / `32` (AKA') のみ許容する。

### 4.4 MAC計算 (Crypto)

`Packet` 構造体のメソッドとして実装します。

- **CalculateAndSetMac:**
    1. パケット内の `AT_MAC` 属性の値を一時的に `0x00...` (16バイト) に置換。
    2. パケット全体を Marshal。
    3. Code/Type に応じて HMAC-SHA1 (AKA) または HMAC-SHA256 (AKA') を計算。
    4. 計算結果を `AT_MAC` に書き戻す。
- **VerifyMac:**
    - 受信した MAC 値と、サーバー側で計算した MAC 値を比較する際、`crypto/subtle.ConstantTimeCompare` を使用してタイミング攻撃を防ぐ。
    - 検証の後、`AT_MAC` の値は元に戻す。
- **追加データ付きの MAC（CalculateAndSetMacWithExtra / VerifyMacWithExtra）:**
    - MAC は「EAP パケット | メッセージ固有のデータ」に対して計算する（RFC 4187 Section 10.15）。EAP-AKA/AKA' でメッセージ固有のデータを使うのは EAP-Response/AKA-Reauthentication だけで、サーバが送った `NONCE_S` をつなぐ（Section 9.8）。
    - 既存の `CalculateAndSetMac` / `VerifyMac` は、追加データなし（nil）で新しいメソッドを呼ぶ。
- **既知の制約:** MAC は受信したバイト列ではなく、解析した構造体から組み立て直したバイト列で計算する。そのため、送信側が予約フィールドを 0 以外にしていると、MAC が正しくても検証に失敗する。

### 4.5 AT_ENCR_DATA（RFC 4187 Section 10.12）

- **EncryptAttributes(kEncr, iv, attrs):** 属性を並べ、長さを 16 で割った余り（0・4・8・12）に応じて 12・8・4 バイトの `AT_PADDING` を付け、K_encr と IV（`AT_IV`）で AES-128-CBC 暗号化する。呼び出し側が `AT_PADDING` を渡したらエラーにする。
- **DecryptAttributes(kEncr, iv, ciphertext):** 暗号文の長さが 16 の正の倍数であることを確認して復号し、属性の並びとして解析する。`AT_PADDING` があれば最後尾にあること（ゼロ埋めは `AtPadding.Unmarshal` が検証）を確かめ、結果から取り除く。そのため `EncryptAttributes` に渡した属性と同じものが返る。
- **NewIV():** 16 バイトの乱数を返す。Go 1.24 以降の `crypto/rand.Read` はエラーを返さないので、エラーを返さない。
- **ライブラリが判定しないこと:** どの属性を入れ子にしてよいかは判定しない（テストツールの準拠性チェックの役割）。未知の属性は `GenericAttribute` として返す。

### 4.6 鍵導出

- **フル認証（EAP-AKA）:** `MK = SHA1(Identity|IK|CK)` を FIPS 186-2 PRF（Change Notice 1）に入れ、K_encr・K_aut・MSK・EMSK を得る。`AkaKeys.MK` に MK を返す。
- **フル認証（EAP-AKA'）:** `MK = PRF'(IK'|CK', "EAP-AKA'"|Identity)` から K_encr・K_aut・K_re・MSK・EMSK を得る。CK'・IK' は `DeriveCKPrimeIKPrime`（TS 33.402 Annex A.2）で導出する。
- **再認証（EAP-AKA）:** `XKEY' = SHA1(Identity|counter|NONCE_S|MK)` を同じ PRF に入れ、出力の先頭 64 バイトを MSK、次の 64 バイトを EMSK にする（`DeriveReauthKeysAKA`）。
- **再認証（EAP-AKA'）:** `MK = PRF'(K_re, "EAP-AKA' re-auth"|Identity|counter|NONCE_S)` の先頭 64 バイトを MSK、次の 64 バイトを EMSK にする（`DeriveReauthKeysAKAPrime`）。
- **再認証の入力:** Identity は末尾の NUL を含まない再認証 ID、counter は 16 bit のビッグエンディアン。NONCE_S は 16 バイト、MK は 20 バイト、K_re は 32 バイトで、違えばエラーにする。K_encr と K_aut は再導出しない。

### 4.7 AT_CHECKCODE（RFC 4187 Section 10.13、RFC 9048 Section 3.4.3）

- **ComputeCheckcode(methodType, packets...):** AKA-Identity の Request / Response の EAP パケット全体（EAP ヘッダを含む）を、送受信したままの形で、送受信した順に区切りなしでつなぎ、SHA-1（AKA、20 バイト）または SHA-256（AKA'、32 バイト）でハッシュする。hostap の `eap_aka.c`（`id_msgs`）と同じ扱い。
- 各パケットが指定した方式の AKA-Identity であること、EAP の Length がパケットの長さと一致すること、Request と Response が交互に並び Identifier が対応することを確かめる。
- パケットを渡さなければ、空のチェックコード（AKA-Identity をやり取りしていないことを表す）を返す。
- どのパケットを含めるか（往復単位で含める、再送は 1 回だけ）は呼び出し側が決める。

### 4.8 MS-MPPE-Send/Recv-Key（RFC 2548 Section 2.4.2-3）

- **EncryptMPPEKey:** 乱数の Salt（最上位ビットは 1）を作り、`b(1) = MD5(S + R + Salt)`、`b(i) = MD5(S + c(i-1))` で「Key-Length | Key | Padding」を暗号化する。本体は Salt を引数で受け取る内部関数にあり、テストで結果を再現できる。
- **DecryptMPPEKey:** 逆の手順で復号する。Salt の後ろが 16 の正の倍数であること、Key-Length が 1 以上で復号結果を超えないことを確かめる。Salt（最上位ビットと重複）とパディングは検査しない（呼び出し側の役割）。

### 4.9 Session-Id（RFC 5247 Appendix A、RFC 9048 Section 6）

- **SessionIDAKA:** `0x17 || RAND || AUTN`。RFC 5247 には EAP-AKA の再認証の定義がない（hostap は EAP-AKA' と同じ形の `0x17 || NONCE_S || MAC` を使う）。
- **SessionIDAKAPrime / SessionIDAKAPrimeReauth:** `0x32 || RAND || AUTN`、`0x32 || NONCE_S || MAC`。

## 5. テスト戦略 (Testing Strategy)

プロトコルスタックの実装において、バイト単位のズレは致命的です。本ライブラリでは `github.com/google/go-cmp/cmp` を導入し、構造体レベルでの厳密な一致確認を行います。

### 5.1 Round-Trip Test (Encode/Decode)

「構造体 -> バイナリ -> (再パース) -> 構造体」の変換を行い、元の構造体と完全に一致することを保証します。

```go
func TestPacket_RoundTrip(t *testing.T) {
    // 1. Arrange: 複雑な構造体を作成
    original := &eapaka.Packet{ ... }

    // 2. Act: Marshal して再度 Parse
    bin, _ := original.Marshal()
    parsed, _ := eapaka.Parse(bin)

    // 3. Assert: go-cmp で詳細比較
    if diff := cmp.Diff(original, parsed); diff != "" {
        t.Errorf("Packet mismatch (-want +got):\n%s", diff)
    }
}
```

### 5.2 RFC準拠レイアウト/制約テスト

Round-Tripだけでは検出しにくい仕様逸脱を防ぐため、属性ごとの専用テストを追加します。

- `AT_RAND` / `AT_AUTN`:
  - RFC形式（`Reserved(2) + 16byte`）のバイト列を直接検証する。
  - Parse時に RFC準拠データを正しく解釈できることを確認する。
- `AT_PADDING`:
  - 許可長（2/6/10）と不許可長を検証する。
  - 非ゼロバイトを拒否することを検証する。
- `AT_CHECKCODE`:
  - 許可長（0/20/32）と不許可長を検証する。

### 5.3 外部実装のテストベクタ

暗号処理（鍵導出、AT_ENCR_DATA、MAC、AT_CHECKCODE、MPPE）は、本ライブラリとは独立した実装から生成したベクタと一致することを確かめる。ベクタは `testdata/vectors/*.json` にコミットしてあり、テストは `encoding/json/v2` で読み込んで `go-cmp` で比較する。

| 生成元 | 対象 |
|---|---|
| hostap 2.12（`eap_sim_common.c` と内蔵の暗号実装にリンクする C プログラム） | フル認証・再認証の鍵、AT_ENCR_DATA、AT_IV・AT_ENCR_DATA・AT_MAC を含む完成したパケット（追加データ付きの MAC、AT_BIDDING を含む違反パケットを含む） |
| Python の標準ライブラリ | MPPE 鍵（hostap の `radius.c` でも照合）、AT_CHECKCODE |

生成プログラムと手順は `tools/vectorgen/README.md` にある。`make -C tools/vectorgen check` で、生成し直した結果がコミット済みのベクタと一致することを確かめられる。

テストの効き目は、実装を一時的に壊した版（counter のバイト順、MAC の追加データ、チェックコードのハッシュなど）でテストが失敗することで確認している。

## 6. ドキュメント方針 (Documentation & Examples)

パッケージの公開にあたり、ユーザーが直感的に利用できるよう GoDoc の機能を最大限活用します。

### 6.1 コメント規約

- **Exportされたシンボル:** すべての Export された型、関数、定数は、その名前で始まるコメントを持つ必要があります。
- **RFC参照:** 仕様に基づいたパラメータには、必ず `See RFC xxxx Section y.y.` の形式で参照元を明記します。
- **リンク:** 関連する型には `[Packet]` のように角括弧を使い、GoDoc上でハイパーリンク化させます。

### 6.2 Runnable Examples (実行可能な例)

`_test.go` ファイル内に `Example` で始まる関数を作成し、pkg.go.dev 上で実行結果と共に表示される「使用例」を提供します。

#### 例: パケット解析の使用例

```go
// ExampleParse demonstrates how to handle incoming EAP packets.
func ExampleParse() {
    // Raw bytes example (EAP-Success)
    raw := []byte{0x03, 0x01, 0x00, 0x04}

    pkt, _ := eapaka.Parse(raw)

    switch pkt.Code {
    case eapaka.CodeSuccess:
        fmt.Println("Auth Success")
    case eapaka.CodeRequest:
        if pkt.Type == eapaka.TypeAKA {
            fmt.Println("AKA Request")
        }
    }
    // Output: Auth Success
}
```

## 7. 対応RFCリファレンス (References)

- **RFC 3748:** Extensible Authentication Protocol (EAP)
- **RFC 4187:** EAP Method for 3rd Gen Authentication and Key Agreement (EAP-AKA)
- **RFC 2548:** Microsoft Vendor-specific RADIUS Attributes（MS-MPPE-Send-Key / MS-MPPE-Recv-Key）
- **RFC 5247:** EAP Key Management Framework（Session-Id）
- **RFC 9048:** Improved EAP Method for 3GPP Mobile Network Authentication and Key Agreement (EAP-AKA')。RFC 5448 を廃止
