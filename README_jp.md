# go-eapaka

[English](README.md) | [日本語](README_jp.md)

`go-eapaka` は、**EAP-AKA (RFC 4187)** および **EAP-AKA' (RFC 9048。RFC 5448 を廃止)** プロトコルを扱うための Go 言語用ライブラリです。
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

### AT_BIDDING (AKA/AKA' ネゴシエーション)

```go
bid := &eapaka.AtBidding{}
bid.SetAKAPrime(true) // AKA' 対応を通知

pkt := &eapaka.Packet{
	Code:       eapaka.CodeRequest,
	Identifier: 1,
	Type:       eapaka.TypeAKA,
	Subtype:    eapaka.SubtypeIdentity,
	Attributes: []eapaka.Attribute{
		bid,
	},
}
```

### 鍵導出 (KDF)

EAP-AKA (RFC 4187) および EAP-AKA' (RFC 9048) 用のセッション鍵を導出します。

```go
// EAP-AKA' の例
identity := "0555444333222111"
ck := ... // USIMから取得
ik := ... // USIMから取得
autn := ... // USIMから取得
netName := "WLAN"

// 1. CK', IK' の導出 (RFC 9048 / TS 33.402)
ckPrime, ikPrime, _ := eapaka.DeriveCKPrimeIKPrime(ck, ik, netName, autn)

// 2. マスターキー (K_encr, K_aut, MSK, EMSK) の導出
keys := eapaka.DeriveKeysAKAPrime(identity, ckPrime, ikPrime)

fmt.Printf("MSK: %x\n", keys.MSK)
```

**EAP-AKA' KDF に関する注意**: `DeriveCKPrimeIKPrime` は TS 33.402 Annex A.2 に準拠し、RFC 9048 Appendix D のテストベクタに一致します。詳細は `kdf_test.go` を参照してください。

### 高速再認証 (Fast Re-authentication)

フル認証で得た `MK`（EAP-AKA）または `K_re`（EAP-AKA'）を保持しておき、高速再認証のたびに新しい MSK と EMSK を導出します（RFC 4187 Section 7、RFC 9048 Section 3.3）。`K_encr` と `K_aut` はフル認証のものを使い続けます。

```go
// EAP-AKA
full := eapaka.DeriveKeysAKA(identity, ck, ik)
reauth, err := eapaka.DeriveReauthKeysAKA(reauthID, counter, nonceS, full.MK)

// EAP-AKA'
fullPrime := eapaka.DeriveKeysAKAPrime(identity, ckPrime, ikPrime)
reauthPrime, err := eapaka.DeriveReauthKeysAKAPrime(reauthID, counter, nonceS, fullPrime.K_re)
```

`reauthID` は末尾の NUL を含まない再認証 ID、`counter` は `AT_COUNTER` の値、`nonceS` は 16 バイトの `AT_NONCE_S` の値です。

#### 暗号化属性 (AT_ENCR_DATA)

`EncryptAttributes` は必要に応じて `AT_PADDING` を付け、属性を AES-128-CBC で暗号化します。`DecryptAttributes` は `AT_PADDING` が最後尾にありゼロで埋まっていることを検証し、取り除いて返します（RFC 4187 Section 10.12）。IV は `AT_ENCR_DATA` ごとに新しく作ってください。

```go
iv := eapaka.NewIV()
encrypted, err := eapaka.EncryptAttributes(full.K_encr, iv, []eapaka.Attribute{
	&eapaka.AtCounter{Counter: 1},
	&eapaka.AtNonceS{NonceS: nonceS},
	&eapaka.AtNextReauthId{Identity: nextReauthID},
})
attrs := []eapaka.Attribute{
	&eapaka.AtIv{IV: iv},
	&eapaka.AtEncrData{EncryptedData: encrypted},
	&eapaka.AtMac{},
}

// 受信側（AT_MAC を検証した後）
nested, err := eapaka.DecryptAttributes(full.K_encr, iv, encrypted)
```

`ParseAttributes` は EAP パケットに包まれていない属性の並びを解析します。未知の属性は `*GenericAttribute` として返り、`IsSkippable` で無視してよい（スキップ可能な）属性かどうかを判定できます（RFC 4187 Section 8.1）。

#### NONCE_S を含む MAC

EAP-Response/AKA-Reauthentication の MAC は、パケットの後ろに `NONCE_S` をつないだものに対して計算します（RFC 4187 Section 9.8）。それ以外のメッセージは `CalculateAndSetMac` と `VerifyMac` を使います。

```go
// ピア
err := resp.CalculateAndSetMacWithExtra(full.K_aut, nonceS)

// サーバ
ok, err := resp.VerifyMacWithExtra(full.K_aut, nonceS)
```

### MS-MPPE-Key 暗号化

RADIUS 属性 `MS-MPPE-Send-Key` および `MS-MPPE-Recv-Key` の暗号化と復号を行います（RFC 2548）。

```go
// MSK を Send/Recv キーに分割
sendKey := keys.MSK[0:32]
recvKey := keys.MSK[32:64]

// 鍵の暗号化 (RADIUS 共有シークレットと Request Authenticator が必要)
secret := []byte("radius-secret")
reqAuth := ... // RADIUS Access-Request から取得した 16バイト

encSendKey, _ := eapaka.EncryptMPPEKey(sendKey, secret, reqAuth)
encRecvKey, _ := eapaka.EncryptMPPEKey(recvKey, secret, reqAuth)

// RADIUS クライアント側: 属性値（Salt + 暗号化された String）を復号する
decrypted, err := eapaka.DecryptMPPEKey(encRecvKey, secret, reqAuth)
```

`DecryptMPPEKey` は Salt を検査しません。最上位ビットが 1 であること（`enc[0]&0x80 != 0`）と、同じ Access-Accept の中で重複しないことは、呼び出し側で確認してください。

### AT_CHECKCODE

`ComputeCheckcode` は、EAP-Request/AKA-Identity と EAP-Response/AKA-Identity のパケットを、送受信したままの形でその順につなぎ、SHA-1（EAP-AKA）または SHA-256（EAP-AKA'）でハッシュします（RFC 4187 Section 10.13、RFC 9048 Section 3.4.3）。パケットを渡さなければ空のチェックコードを返します。

```go
checkcode, err := eapaka.ComputeCheckcode(eapaka.TypeAKA, req1, resp1, req2, resp2)
attr := &eapaka.AtCheckcode{Checkcode: checkcode}
```

### Notification のコード値

`AtNotification.Code` は下位 14 bit だけを持ちます。RFC 4187 Section 10.19 の 16 bit のコード値（S ビット 0x8000 と P ビット 0x4000 を含む）とは、`NewNotification` と `FullCode` で変換します。

```go
attr := eapaka.NewNotification(eapaka.NotificationGeneralFailure) // S = 0, P = 1

if received.FullCode() == eapaka.NotificationSuccess {
	// ...
}
```

定数: `NotificationGeneralFailureAfterAuth` (0)、`NotificationTemporarilyDenied` (1026)、`NotificationNotSubscribed` (1031)、`NotificationGeneralFailure` (16384)、`NotificationSuccess` (32768)。

### エクスポートパラメータ (Session-Id)

- `SessionIDAKA(rand, autn)`: EAP-AKA、`0x17 || RAND || AUTN`（RFC 5247 Appendix A）
- `SessionIDAKAPrime(rand, autn)`、`SessionIDAKAPrimeReauth(nonceS, mac)`: EAP-AKA'（RFC 9048 Section 6）
- `PeerIDFromAttributes`、`ServerIDAKAPrime`

### 解析オプション

`Parse` は EAP-AKA' のパケットに含まれる `AT_BIDDING` をエラーにします（RFC 9048 Section 4）。テストツールが違反を報告するために、こうしたパケットを受け付けることができます。

```go
pkt, err := eapaka.ParseWithOptions(data, eapaka.ParseOptions{AllowBiddingInAKAPrime: true})
ok, err := pkt.VerifyMac(kAut) // MAC の関数は AT_BIDDING を受け付ける。Marshal は引き続き拒否する
```

## サポートしている属性

**注意**: 本ライブラリは属性ヘッダー (Type, Length) とパディングの処理のみを行います。属性値（データ部分）については、RFCの定義に従って利用者自身がバイト列を構築し、対応するフィールド（`Rand`, `Autn`, `Identity` 等）に格納する必要があります。`AT_RAND` と `AT_AUTN` は 16バイトの `Rand`/`Autn` だけを指定してください（`Reserved(2)` はライブラリ内部で処理されます）。

- **認証・鍵生成**: `AT_RAND`, `AT_AUTN`, `AT_RES`, `AT_AUTS`, `AT_MAC`
- **ID管理**: `AT_IDENTITY`, `AT_PERMANENT_ID_REQ`, `AT_ANY_ID_REQ`, `AT_FULLAUTH_ID_REQ`
- **通知・エラー**: `AT_NOTIFICATION`, `AT_CLIENT_ERROR_CODE`
- **再認証・仮名**: `AT_COUNTER`, `AT_COUNTER_TOO_SMALL`, `AT_NONCE_S`, `AT_NEXT_PSEUDONYM`, `AT_NEXT_REAUTH_ID`
- **暗号化**: `AT_IV`, `AT_ENCR_DATA`, `AT_PADDING`
- **EAP-AKA' 拡張**: `AT_KDF`, `AT_KDF_INPUT`, `AT_BIDDING` (flags: `AtBiddingFlagAKAPrime`)
- **その他**: `AT_CHECKCODE`, `AT_RESULT_IND`, `AT_NONCE_MT`, `AT_VERSION_LIST`, `AT_SELECTED_VERSION`

## テストベクタ

暗号処理の関数は、本ライブラリとは独立した実装である hostap 2.12（hostapd / wpa_supplicant）と Python の標準ライブラリから生成したベクタで検証しています。ベクタは `testdata/vectors` にあり、生成プログラムと再生成・照合の手順は `tools/vectorgen` にあります（`make -C tools/vectorgen check`）。

## v0.2.0 の変更点

追加した API（既存の関数・メソッドの削除やシグネチャの変更はありません）:

- 高速再認証の鍵: `ReauthKeys`、`DeriveReauthKeysAKA`、`DeriveReauthKeysAKAPrime`、`AkaKeys.MK`（末尾に追加したフィールド）
- AT_ENCR_DATA: `EncryptAttributes`、`DecryptAttributes`、`NewIV`、`ParseAttributes`、`IsSkippable`
- 追加データ付きの MAC: `Packet.CalculateAndSetMacWithExtra`、`Packet.VerifyMacWithExtra`
- `ComputeCheckcode`、`NewNotification`、`AtNotification.FullCode`、`Notification*` 定数、`SessionIDAKA`
- `DecryptMPPEKey`、`ParseOptions`、`ParseWithOptions`

互換性に関する注意:

- `AkaKeys` にフィールドを追加したため、フィールド名を書かない `AkaKeys` の複合リテラルはコンパイルできなくなります。フィールド名を書いたリテラルや、`DeriveKeysAKA` の戻り値を使うコードには影響しません。
- MAC の関数は、`AT_BIDDING` を含む EAP-AKA' のパケットについて、エラーを返す代わりに MAC を計算・検証するようになりました。`Marshal` と `Parse` は引き続きこうしたパケットを拒否します。

## RFC準拠アップデート (2026-02-20)

RFC 4187 / RFC 5448 との整合性を高めるため、以下を修正しました。

- `AT_RAND` / `AT_AUTN` の Value を `Reserved(2) + RAND/AUTN(16)` 形式で Marshal/Unmarshal するように修正（RFC 4187 準拠）。
- `AT_PADDING` の検証を強化:
  - Value長は `2` / `6` / `10` バイトのみ許可（属性全体長では `4` / `8` / `12` バイト）。
  - Unmarshal時、全バイトが `0x00` であることを検証。
- `AT_CHECKCODE` の長さ制約を追加（`0` / `20` / `32` バイトのみ許可）。

互換性に関する注意:

- これまでの非準拠な入力に依存していた場合、Marshal/Unmarshal の結果が変わる可能性があります。
- RFC準拠の相手機器との相互接続性は、`AT_RAND` / `AT_AUTN` で改善されます。

## 参考文献

- [RFC 2548: Microsoft Vendor-specific RADIUS Attributes](https://www.rfc-editor.org/rfc/rfc2548)
- [RFC 3748: Extensible Authentication Protocol (EAP)](https://tools.ietf.org/html/rfc3748)
- [RFC 4187: EAP Method for 3rd Generation Authentication and Key Agreement (EAP-AKA)](https://tools.ietf.org/html/rfc4187)
- [RFC 5247: Extensible Authentication Protocol (EAP) Key Management Framework](https://www.rfc-editor.org/rfc/rfc5247)
- [RFC 9048: Improved Extensible Authentication Protocol Method for 3GPP Mobile Network Authentication and Key Agreement (EAP-AKA')](https://www.rfc-editor.org/rfc/rfc9048)（RFC 5448 を廃止）

## ライセンス

MIT
