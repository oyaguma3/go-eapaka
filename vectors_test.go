package eapaka

import (
	"bytes"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// このファイルは、外部実装（hostap と Python）から生成したテストベクタ
// （testdata/vectors/*.json）を読み込む仕組みと、それを使った既存 API の検証をまとめる。
// ベクタの生成方法は tools/vectorgen/README.md を参照。

// hexBytes は JSON の 16 進文字列を []byte として読み込む。空文字列は nil になる。
type hexBytes []byte

func (b *hexBytes) UnmarshalText(text []byte) error {
	v, err := hex.AppendDecode(nil, text)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// vectorFile はベクタファイル共通の形。
type vectorFile[T any] struct {
	Source    string `json:"source"`
	Generator string `json:"generator"`
	Cases     []T    `json:"cases"`
}

// loadVectors は testdata/vectors/name を読み込み、ケースの一覧を返す。
// 想定外のメンバーがあれば失敗させ、ベクタと型定義のずれに気付けるようにする。
func loadVectors[T any](t *testing.T, name string) []T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f vectorFile[T]
	if err := json.Unmarshal(data, &f, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if f.Source == "" || f.Generator == "" || len(f.Cases) == 0 {
		t.Fatalf("%s: source, generator or cases is missing", name)
	}
	return f.Cases
}

// vectorMethodType はベクタの "method"（"aka" / "aka_prime"）を EAP の Type に変換する。
func vectorMethodType(t *testing.T, method string) uint8 {
	t.Helper()
	switch method {
	case "aka":
		return TypeAKA
	case "aka_prime":
		return TypeAKAPrime
	}
	t.Fatalf("unknown method %q", method)
	return 0
}

// akaKeysVector は aka_keys.json の 1 ケース（RFC 4187 §7 のフル認証）。
type akaKeysVector struct {
	Name     string   `json:"name"`
	Identity string   `json:"identity"`
	IK       hexBytes `json:"ik"`
	CK       hexBytes `json:"ck"`
	MK       hexBytes `json:"mk"`
	KEncr    hexBytes `json:"k_encr"`
	KAut     hexBytes `json:"k_aut"`
	MSK      hexBytes `json:"msk"`
	EMSK     hexBytes `json:"emsk"`
}

// akaPrimeKeysVector は aka_prime_keys.json の 1 ケース（RFC 9048 §3.3 のフル認証）。
type akaPrimeKeysVector struct {
	Name        string   `json:"name"`
	Identity    string   `json:"identity"`
	NetworkName string   `json:"network_name"`
	AUTN        hexBytes `json:"autn"`
	IK          hexBytes `json:"ik"`
	CK          hexBytes `json:"ck"`
	IKPrime     hexBytes `json:"ik_prime"`
	CKPrime     hexBytes `json:"ck_prime"`
	KEncr       hexBytes `json:"k_encr"`
	KAut        hexBytes `json:"k_aut"`
	KRe         hexBytes `json:"k_re"`
	MSK         hexBytes `json:"msk"`
	EMSK        hexBytes `json:"emsk"`
}

// reauthAKAVector は reauth_keys_aka.json の 1 ケース（RFC 4187 §7 の再認証）。
// XKeyPrime は中間値の XKEY' = SHA1(Identity|counter|NONCE_S|MK)。
type reauthAKAVector struct {
	Name      string   `json:"name"`
	Identity  string   `json:"identity"`
	Counter   uint16   `json:"counter"`
	NonceS    hexBytes `json:"nonce_s"`
	MK        hexBytes `json:"mk"`
	XKeyPrime hexBytes `json:"xkey_prime"`
	MSK       hexBytes `json:"msk"`
	EMSK      hexBytes `json:"emsk"`
}

// reauthAKAPrimeVector は reauth_keys_aka_prime.json の 1 ケース（RFC 9048 §3.3 の再認証）。
type reauthAKAPrimeVector struct {
	Name     string   `json:"name"`
	Identity string   `json:"identity"`
	Counter  uint16   `json:"counter"`
	NonceS   hexBytes `json:"nonce_s"`
	KRe      hexBytes `json:"k_re"`
	MSK      hexBytes `json:"msk"`
	EMSK     hexBytes `json:"emsk"`
}

// encrDataVector は encr_data.json の 1 ケース（RFC 4187 §10.12 の AT_ENCR_DATA）。
// Attributes はパディング前の属性の並び、Plaintext は AT_PADDING を付けた平文。
// PaddingLen は AT_PADDING 全体のバイト数（0・4・8・12）。
type encrDataVector struct {
	Name       string   `json:"name"`
	KEncr      hexBytes `json:"k_encr"`
	IV         hexBytes `json:"iv"`
	Attributes hexBytes `json:"attributes"`
	PaddingLen int      `json:"padding_len"`
	Plaintext  hexBytes `json:"plaintext"`
	Ciphertext hexBytes `json:"ciphertext"`
}

// packetVector は packets.json の 1 ケース。AT_IV・AT_ENCR_DATA・AT_MAC を含む
// 完成したパケットと、その生成に使った鍵などを持つ。
// IV と Plaintext は AT_ENCR_DATA がなければ空。Extra は MAC の計算で
// パケットの後ろにつなぐ追加データ（RFC 4187 §9.8 の NONCE_S など）。
type packetVector struct {
	Name      string   `json:"name"`
	Method    string   `json:"method"`
	KEncr     hexBytes `json:"k_encr"`
	KAut      hexBytes `json:"k_aut"`
	IV        hexBytes `json:"iv"`
	Plaintext hexBytes `json:"plaintext"`
	Extra     hexBytes `json:"extra"`
	MAC       hexBytes `json:"mac"`
	Packet    hexBytes `json:"packet"`
}

// mppeVector は mppe.json の 1 ケース（RFC 2548 §2.4.2）。
// Plaintext は Key-Length・鍵・パディングからなる暗号化前の値、
// Encrypted は Salt を先頭に付けた属性値。
type mppeVector struct {
	Name      string   `json:"name"`
	Secret    hexBytes `json:"secret"`
	ReqAuth   hexBytes `json:"req_auth"`
	Salt      hexBytes `json:"salt"`
	Key       hexBytes `json:"key"`
	Plaintext hexBytes `json:"plaintext"`
	Encrypted hexBytes `json:"encrypted"`
}

// checkcodeVector は checkcode.json の 1 ケース（RFC 4187 §10.13、RFC 9048 §3.4.3）。
// Packets は送受信した順の AKA-Identity パケット。やり取りがなければ空で、
// そのとき Checkcode も空になる。
type checkcodeVector struct {
	Name      string     `json:"name"`
	Method    string     `json:"method"`
	Packets   []hexBytes `json:"packets"`
	Checkcode hexBytes   `json:"checkcode"`
}

// -----------------------------------------------------------------------------
// 既存 API の検証
// -----------------------------------------------------------------------------

func TestVectors_DeriveKeysAKA(t *testing.T) {
	for _, v := range loadVectors[akaKeysVector](t, "aka_keys.json") {
		t.Run(v.Name, func(t *testing.T) {
			got := DeriveKeysAKA(v.Identity, v.CK, v.IK)
			want := AkaKeys{K_encr: v.KEncr, K_aut: v.KAut, MSK: v.MSK, EMSK: v.EMSK}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("DeriveKeysAKA mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVectors_DeriveKeysAKAPrime(t *testing.T) {
	for _, v := range loadVectors[akaPrimeKeysVector](t, "aka_prime_keys.json") {
		t.Run(v.Name, func(t *testing.T) {
			ckPrime, ikPrime, err := DeriveCKPrimeIKPrime(v.CK, v.IK, v.NetworkName, v.AUTN)
			if err != nil {
				t.Fatalf("DeriveCKPrimeIKPrime: %v", err)
			}
			if diff := cmp.Diff([]byte(v.CKPrime), ckPrime); diff != "" {
				t.Errorf("CK' mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff([]byte(v.IKPrime), ikPrime); diff != "" {
				t.Errorf("IK' mismatch (-want +got):\n%s", diff)
			}

			got := DeriveKeysAKAPrime(v.Identity, ckPrime, ikPrime)
			want := AkaPrimeKeys{K_encr: v.KEncr, K_aut: v.KAut, K_re: v.KRe, MSK: v.MSK, EMSK: v.EMSK}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("DeriveKeysAKAPrime mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestVectors_PrfGenAKA_ReauthXKey は、再認証の XKEY' を入力にした FIPS 186-2 PRF の
// 出力が hostap の MSK|EMSK と一致することを確かめる。
// XKEY' の組み立て自体は P0-3 の DeriveReauthKeysAKA で検証する。
func TestVectors_PrfGenAKA_ReauthXKey(t *testing.T) {
	for _, v := range loadVectors[reauthAKAVector](t, "reauth_keys_aka.json") {
		t.Run(v.Name, func(t *testing.T) {
			got := prfGenAKA(v.XKeyPrime, 128)
			if diff := cmp.Diff([]byte(v.MSK), got[:64]); diff != "" {
				t.Errorf("MSK mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff([]byte(v.EMSK), got[64:]); diff != "" {
				t.Errorf("EMSK mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestVectors_Packets_ParseMarshal は、hostap が組み立てたパケットを Parse して
// Marshal し直すと元のバイト列に戻ることと、AT_IV・AT_ENCR_DATA・AT_MAC の値を確かめる。
func TestVectors_Packets_ParseMarshal(t *testing.T) {
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		t.Run(v.Name, func(t *testing.T) {
			p, err := Parse(v.Packet)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got, want := p.Type, vectorMethodType(t, v.Method); got != want {
				t.Errorf("Type = %d, want %d", got, want)
			}

			var iv, encr, mac []byte
			for _, a := range p.Attributes {
				switch a := a.(type) {
				case *AtIv:
					iv = a.IV
				case *AtEncrData:
					encr = a.EncryptedData
				case *AtMac:
					mac = a.MAC
				}
			}
			if diff := cmp.Diff([]byte(v.IV), iv); diff != "" {
				t.Errorf("AT_IV mismatch (-want +got):\n%s", diff)
			}
			if len(encr) != len(v.Plaintext) {
				t.Errorf("AT_ENCR_DATA length = %d, want %d", len(encr), len(v.Plaintext))
			}
			if diff := cmp.Diff([]byte(v.MAC), mac); diff != "" {
				t.Errorf("AT_MAC mismatch (-want +got):\n%s", diff)
			}

			b, err := p.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Packet), b); diff != "" {
				t.Errorf("Marshal mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestVectors_Packets_Mac は既存の VerifyMac・CalculateAndSetMac（追加データなし）を
// hostap の MAC と照合する。追加データを使うパケットでは、追加データなしの検証が
// 失敗することだけを確かめる（追加データ付きの MAC は P0-4 で検証する）。
func TestVectors_Packets_Mac(t *testing.T) {
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		t.Run(v.Name, func(t *testing.T) {
			p, err := Parse(v.Packet)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			ok, err := p.VerifyMac(v.KAut)
			if err != nil {
				t.Fatalf("VerifyMac: %v", err)
			}
			if want := len(v.Extra) == 0; ok != want {
				t.Fatalf("VerifyMac = %v, want %v", ok, want)
			}
			if len(v.Extra) != 0 {
				return
			}

			if err := p.CalculateAndSetMac(v.KAut); err != nil {
				t.Fatalf("CalculateAndSetMac: %v", err)
			}
			b, err := p.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if diff := cmp.Diff([]byte(v.Packet), b); diff != "" {
				t.Errorf("packet after CalculateAndSetMac mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// ベクタファイル自体の整合性
// （対応する API はまだないが、形式の誤りに早く気付けるようにする）
// -----------------------------------------------------------------------------

func TestVectors_ReauthAKAPrimeConsistency(t *testing.T) {
	for _, v := range loadVectors[reauthAKAPrimeVector](t, "reauth_keys_aka_prime.json") {
		t.Run(v.Name, func(t *testing.T) {
			if v.Identity == "" || len(v.NonceS) != 16 || len(v.KRe) != 32 || len(v.MSK) != 64 || len(v.EMSK) != 64 {
				t.Errorf("identity/NONCE_S/K_re/MSK/EMSK length = %d/%d/%d/%d/%d, want >0/16/32/64/64",
					len(v.Identity), len(v.NonceS), len(v.KRe), len(v.MSK), len(v.EMSK))
			}
		})
	}
}

func TestVectors_EncrDataConsistency(t *testing.T) {
	seen := map[int]bool{}
	for _, v := range loadVectors[encrDataVector](t, "encr_data.json") {
		t.Run(v.Name, func(t *testing.T) {
			if len(v.KEncr) != 16 || len(v.IV) != 16 {
				t.Fatalf("K_encr/IV length = %d/%d, want 16/16", len(v.KEncr), len(v.IV))
			}
			if len(v.Ciphertext) == 0 || len(v.Ciphertext)%16 != 0 || len(v.Plaintext) != len(v.Ciphertext) {
				t.Fatalf("plaintext/ciphertext length = %d/%d", len(v.Plaintext), len(v.Ciphertext))
			}
			if len(v.Attributes)+v.PaddingLen != len(v.Plaintext) || !bytes.HasPrefix(v.Plaintext, v.Attributes) {
				t.Fatalf("attributes (%d bytes) + padding (%d) do not form the plaintext", len(v.Attributes), v.PaddingLen)
			}
			attrs, err := ParseAttributes(v.Plaintext)
			if err != nil {
				t.Fatalf("parse plaintext: %v", err)
			}
			if v.PaddingLen != 0 {
				pad, ok := attrs[len(attrs)-1].(*AtPadding)
				if !ok || pad.Length+2 != v.PaddingLen {
					t.Fatalf("last attribute is not AT_PADDING of %d bytes: %#v", v.PaddingLen, attrs[len(attrs)-1])
				}
			}
		})
		seen[v.PaddingLen] = true
	}
	for _, n := range []int{0, 4, 8, 12} {
		if !seen[n] {
			t.Errorf("no case with padding_len %d", n)
		}
	}
}

func TestVectors_MPPEConsistency(t *testing.T) {
	for _, v := range loadVectors[mppeVector](t, "mppe.json") {
		t.Run(v.Name, func(t *testing.T) {
			if len(v.ReqAuth) != 16 || len(v.Salt) != 2 || v.Salt[0]&0x80 == 0 {
				t.Fatalf("invalid Request Authenticator or Salt")
			}
			if len(v.Plaintext)%16 != 0 || int(v.Plaintext[0]) != len(v.Key) ||
				!bytes.Equal(v.Plaintext[1:1+len(v.Key)], v.Key) {
				t.Fatalf("plaintext is not Key-Length | key | padding")
			}
			if len(v.Encrypted) != 2+len(v.Plaintext) || !bytes.HasPrefix(v.Encrypted, v.Salt) {
				t.Fatalf("encrypted is not Salt | ciphertext")
			}
		})
	}
}

func TestVectors_CheckcodeConsistency(t *testing.T) {
	for _, v := range loadVectors[checkcodeVector](t, "checkcode.json") {
		t.Run(v.Name, func(t *testing.T) {
			typ := vectorMethodType(t, v.Method)
			wantLen := map[uint8]int{TypeAKA: 20, TypeAKAPrime: 32}[typ]
			if len(v.Packets) == 0 {
				wantLen = 0
			}
			if len(v.Checkcode) != wantLen {
				t.Errorf("checkcode length = %d, want %d", len(v.Checkcode), wantLen)
			}
			for i, raw := range v.Packets {
				p, err := Parse(raw)
				if err != nil {
					t.Fatalf("packet %d: Parse: %v", i, err)
				}
				// Request と Response が交互に並ぶ
				wantCode := CodeRequest
				if i%2 == 1 {
					wantCode = CodeResponse
				}
				if p.Code != wantCode || p.Type != typ || p.Subtype != SubtypeIdentity {
					t.Errorf("packet %d: code/type/subtype = %d/%d/%d, want %d/%d/%d",
						i, p.Code, p.Type, p.Subtype, wantCode, typ, SubtypeIdentity)
				}
			}
		})
	}
}
