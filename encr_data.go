package eapaka

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
)

// AT_ENCR_DATA (RFC 4187 Section 10.12) carries nested attributes such as
// AT_NEXT_PSEUDONYM, AT_NEXT_REAUTH_ID, AT_COUNTER, AT_COUNTER_TOO_SMALL,
// AT_NONCE_S and AT_PADDING, encrypted with AES-128 in CBC mode using K_encr
// and the initialization vector carried in AT_IV.

const (
	encrKeyLen = 16 // K_encr
	ivLen      = 16 // AT_IV の Initialization Vector
)

// NewIV returns a new random 16-byte initialization vector for AT_IV.
// The sender must not reuse an IV from previous packets (RFC 4187 Section 10.12).
func NewIV() []byte {
	iv := make([]byte, ivLen)
	rand.Read(iv) // Go 1.24 以降の crypto/rand.Read はエラーを返さない
	return iv
}

// EncryptAttributes marshals attrs in order, appends AT_PADDING when needed so
// that the plaintext length is a multiple of 16 bytes, and encrypts the result
// with AES-128-CBC. The returned bytes are the Encrypted Data of AT_ENCR_DATA
// (AtEncrData.EncryptedData).
//
// kEncr is K_encr (16 bytes) and iv is the Initialization Vector of AT_IV
// (16 bytes), for example from NewIV. attrs must not be empty and must not
// contain AT_PADDING, which EncryptAttributes adds itself.
func EncryptAttributes(kEncr, iv []byte, attrs []Attribute) ([]byte, error) {
	block, err := newEncrCipher(kEncr, iv)
	if err != nil {
		return nil, err
	}
	if len(attrs) == 0 {
		return nil, errors.New("no attributes to encrypt")
	}

	var plain []byte
	for _, a := range attrs {
		if a.Type() == AT_PADDING {
			return nil, errors.New("AT_PADDING must not be given; it is added automatically")
		}
		b, err := a.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshal attribute type %d: %w", a.Type(), err)
		}
		if len(b) == 0 || len(b)%4 != 0 {
			return nil, fmt.Errorf("attribute type %d: marshaled length %d is not a positive multiple of 4", a.Type(), len(b))
		}
		plain = append(plain, b...)
	}

	// 属性の長さは 4 の倍数なので、16 で割った余りは 0・4・8・12 のどれか。
	// 余りが 0 でなければ、属性全体で 12・8・4 バイトの AT_PADDING を付ける。
	// AtPadding.Length は値部分の長さなので、ヘッダの 2 バイトを引く。
	if rem := len(plain) % aes.BlockSize; rem != 0 {
		pad, err := (&AtPadding{Length: aes.BlockSize - rem - 2}).Marshal()
		if err != nil {
			return nil, err
		}
		plain = append(plain, pad...)
	}

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plain, plain)
	return plain, nil
}

// DecryptAttributes decrypts the Encrypted Data of AT_ENCR_DATA with
// AES-128-CBC and parses the plaintext as nested attributes.
//
// kEncr is K_encr (16 bytes) and iv is the Initialization Vector of AT_IV
// (16 bytes). The ciphertext length must be a positive multiple of 16 bytes,
// and the plaintext must consist of whole attributes. If the plaintext contains
// AT_PADDING, it must be the last attribute and its pad bytes must be zero
// (RFC 4187 Section 10.12). A valid AT_PADDING is removed from the result, so
// the result matches the attributes given to EncryptAttributes.
//
// Attributes of unknown types are returned as *GenericAttribute (see
// IsSkippable). DecryptAttributes does not check which attributes are allowed
// in AT_ENCR_DATA.
//
// Decrypting with a wrong key or IV usually fails to parse, but this is not
// guaranteed; verify AT_MAC before decrypting.
func DecryptAttributes(kEncr, iv, ciphertext []byte) ([]Attribute, error) {
	block, err := newEncrCipher(kEncr, iv)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AT_ENCR_DATA length %d is not a positive multiple of %d", len(ciphertext), aes.BlockSize)
	}

	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)

	// AT_PADDING の長さとゼロ埋めは AtPadding.Unmarshal が検証する
	attrs, err := ParseAttributes(plain)
	if err != nil {
		return nil, fmt.Errorf("parse decrypted AT_ENCR_DATA: %w", err)
	}
	if i := slices.IndexFunc(attrs, func(a Attribute) bool { return a.Type() == AT_PADDING }); i >= 0 {
		if i != len(attrs)-1 {
			return nil, errors.New("AT_PADDING is not the last attribute in AT_ENCR_DATA")
		}
		attrs = attrs[:i]
	}
	return attrs, nil
}

func newEncrCipher(kEncr, iv []byte) (cipher.Block, error) {
	if len(kEncr) != encrKeyLen {
		return nil, fmt.Errorf("K_encr must be %d bytes, got %d", encrKeyLen, len(kEncr))
	}
	if len(iv) != ivLen {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", ivLen, len(iv))
	}
	return aes.NewCipher(kEncr)
}
