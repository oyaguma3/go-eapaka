# go-eapaka: Design Document

## 1. プロジェクト概要 (Overview)

`go-eapaka` は、**EAP-AKA (RFC 4187)** および **EAP-AKA' (RFC 5448)** プロトコルを扱うための Go 言語用ライブラリです。

RADIUSサーバーや通信テストツールの開発において、EAPパケットの **生成 (Marshal)** と **解析 (Unmarshal)** の双方を厳密かつ容易に行うことを目的としています。

### 設計思想

- **Zero External Dependencies:** プロダクションコードは標準ライブラリ（`encoding/binary`, `crypto/*`）のみで構成し、高い移植性と保守性を確保する。
- **RFC Compliance:** RFC 3748 (EAP), RFC 4187 (EAP-AKA), RFC 5448 (EAP-AKA') に準拠し、エッジケース（EAP-Success/Failureなど）も正しく扱う。
- **Security First:** MAC計算時のゼロ埋め処理や、タイミング攻撃対策（定数時間比較）をライブラリ内部に隠蔽する。
- **Developer Friendly:** `go-cmp` を活用した堅牢なテストと、GoDoc で閲覧しやすいドキュメント構造を提供する。

## 2. パッケージ構成 (Package Structure)

単一責任の原則に基づき、以下のファイル構成を採用します。パッケージレベルのドキュメントは `doc.go` に集約します。

```
go-eapaka/
├── doc.go                # package eapaka の概要、インストール方法、全体的な使用例
├── packet.go             # Packet構造体, 定数定義
├── packet_marshal.go     # Marshal (Packet -> []byte)
├── packet_unmarshal.go   # Parse ([]byte -> Packet)
├── attributes.go         # Attributeインターフェース, 個別の構造体 (AT_RAND等)
├── attributes_decoder.go # Attribute解析用のファクトリー関数
├── crypto.go             # MAC (HMAC-SHA1/256) 計算・検証ロジック
├── types.go              # 型定義 (EAPCode, AttributeType等)
└── packet_test.go        # go-cmpを用いたテスト および Exampleコード
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

RFC 4187 および RFC 5448 で定義される以下の属性を実装しています。

- **認証・鍵生成関連:** `AT_RAND`, `AT_AUTN`, `AT_RES`, `AT_AUTS`, `AT_MAC`
- **ID要求・応答:** `AT_PERMANENT_ID_REQ`, `AT_ANY_ID_REQ`, `AT_FULLAUTH_ID_REQ`, `AT_IDENTITY`
- **通知・エラー:** `AT_NOTIFICATION`, `AT_CLIENT_ERROR_CODE`
- **再認証・仮名:** `AT_NEXT_PSEUDONYM`, `AT_NEXT_REAUTH_ID`, `AT_COUNTER`, `AT_COUNTER_TOO_SMALL`, `AT_NONCE_S`
- **暗号化:** `AT_IV`, `AT_ENCR_DATA`, `AT_PADDING`
- **EAP-AKA' 拡張:** `AT_KDF`, `AT_KDF_INPUT`, `AT_BIDDING`
- **その他:** `AT_CHECKCODE`, `AT_RESULT_IND`, `AT_NONCE_MT`, `AT_VERSION_LIST`, `AT_SELECTED_VERSION`

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

### 4.2 Marshal (Construction) フロー

- **Length Calculation:** パケット全体の Length、各属性の Length（4バイトワード単位）を自動計算。
- **Padding:** EAP-AKAの仕様に従い、各属性が **4バイト境界（32-bit boundary）** に整合するよう、末尾に `0x00` パディングを自動付与。

### 4.3 MAC計算 (Crypto)

`Packet` 構造体のメソッドとして実装します。

- **CalculateAndSetMac:**
    1. パケット内の `AT_MAC` 属性の値を一時的に `0x00...` (16バイト) に置換。
    2. パケット全体を Marshal。
    3. Code/Type に応じて HMAC-SHA1 (AKA) または HMAC-SHA256 (AKA') を計算。
    4. 計算結果を `AT_MAC` に書き戻す。
- **VerifyMac:**
    - 受信した MAC 値と、サーバー側で計算した MAC 値を比較する際、`crypto/subtle.ConstantTimeCompare` を使用してタイミング攻撃を防ぐ。

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
- **RFC 5448:** Improved EAP Method for 3rd Gen Authentication and Key Agreement (EAP-AKA')
