# go-eapaka

[English](README.md) | [日本語](README_jp.md)

`go-eapaka` は、**EAP-AKA (RFC 4187)** および **EAP-AKA' (RFC 5448)** プロトコルを扱うための Go 言語用ライブラリです。
RADIUSサーバー、EAPピア、または通信テストツールの開発において、EAPパケットの **生成 (Marshal)** と **解析 (Unmarshal)** を厳密かつ容易に行うために設計されています。

## 特徴

- **外部依存なし (Zero External Dependencies)**: 標準ライブラリ (`encoding/binary`, `crypto/*`) のみで構築されています。
- **セキュリティ重視**: タイミング攻撃を防ぐための定数時間MAC検証を実装しています。

## インストール

```bash
go get github.com/oyaguma3/go-eapaka
```

## 使い方

### EAPパケットの解析 (Parse)

```go
package main

import (
	"fmt"
	"github.com/oyaguma3/go-eapaka"
)

func main() {
	// 受信したバイト列の例 (EAP-Request/AKA-Identity)
	data := []byte{...}

	pkt, err := eapaka.Parse(data)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Code: %d, Type: %d\n", pkt.Code, pkt.Type)
	
	for _, attr := range pkt.Attributes {
		switch a := attr.(type) {
		case *eapaka.AtIdentity:
			fmt.Printf("Identity: %s\n", a.Identity)
		}
	}
}
```

### EAPパケットの生成 (Marshal)

```go
package main

import (
	"github.com/oyaguma3/go-eapaka"
)

func main() {
	pkt := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			&eapaka.AtRand{Rand: make([]byte, 16)}, // 実際のRANDを設定
			&eapaka.AtAutn{Autn: make([]byte, 16)}, // 実際のAUTNを設定
			&eapaka.AtMac{MAC: make([]byte, 16)},   // MAC計算用のプレースホルダー
		},
	}

	// MACの計算と設定 (K_aut が必要)
	// kAut := ...
	// pkt.CalculateAndSetMac(kAut)

	data, err := pkt.Marshal()
	if err != nil {
		panic(err)
	}
	
	// data を送信...
}
```

## サポートしている属性

**注意**: 本ライブラリは属性ヘッダー (Type, Length) とパディングの処理のみを行います。属性値（データ部分）については、RFCの定義に従って利用者自身がバイト列を構築し、対応するフィールド（`Rand`, `Autn`, `Identity` 等）に格納する必要があります。

- **認証・鍵生成**: `AT_RAND`, `AT_AUTN`, `AT_RES`, `AT_AUTS`, `AT_MAC`
- **ID管理**: `AT_IDENTITY`, `AT_PERMANENT_ID_REQ`, `AT_ANY_ID_REQ`, `AT_FULLAUTH_ID_REQ`
- **通知・エラー**: `AT_NOTIFICATION`, `AT_CLIENT_ERROR_CODE`
- **再認証・仮名**: `AT_COUNTER`, `AT_COUNTER_TOO_SMALL`, `AT_NONCE_S`, `AT_NEXT_PSEUDONYM`, `AT_NEXT_REAUTH_ID`
- **暗号化**: `AT_IV`, `AT_ENCR_DATA`, `AT_PADDING`
- **EAP-AKA' 拡張**: `AT_KDF`, `AT_KDF_INPUT`, `AT_BIDDING`
- **その他**: `AT_CHECKCODE`, `AT_RESULT_IND`, `AT_NONCE_MT`, `AT_VERSION_LIST`, `AT_SELECTED_VERSION`

## 参考文献

- [RFC 3748: Extensible Authentication Protocol (EAP)](https://tools.ietf.org/html/rfc3748)
- [RFC 4187: EAP Method for 3rd Generation Authentication and Key Agreement (EAP-AKA)](https://tools.ietf.org/html/rfc4187)
- [RFC 5448: Improved EAP Method for 3rd Generation Authentication and Key Agreement (EAP-AKA')](https://tools.ietf.org/html/rfc5448)

## ライセンス

MIT
