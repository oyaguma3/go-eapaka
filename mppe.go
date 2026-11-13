package eapaka

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"slices"
)

// EncryptMPPEKey encrypts the given key (e.g., MSK part) for inclusion in
// MS-MPPE-Send-Key or MS-MPPE-Recv-Key attributes.
//
// Ref: RFC 2548 Section 2.4.2 and 2.4.3
// key: The key to encrypt (typically 32 bytes).
// secret: The RADIUS shared secret.
// reqAuth: The Request Authenticator from the Access-Request packet (16 bytes).
func EncryptMPPEKey(key []byte, secret []byte, reqAuth []byte) ([]byte, error) {
	// 1. Generate Salt (2 bytes)
	// "The most significant bit ... MUST be set"
	salt := make([]byte, 2)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	salt[0] |= 0x80

	return encryptMPPEKeyWithSalt(key, secret, reqAuth, salt)
}

// encryptMPPEKeyWithSalt は Salt を指定して鍵を暗号化する（RFC 2548 §2.4.2）。
// EncryptMPPEKey が乱数の Salt で呼ぶほか、テストで結果を再現するために使う。
func encryptMPPEKeyWithSalt(key, secret, reqAuth, salt []byte) ([]byte, error) {
	if len(key) == 0 || len(key) > 255 {
		return nil, errors.New("eapaka: invalid key length for MPPE encryption")
	}
	if len(reqAuth) != 16 {
		return nil, errors.New("eapaka: invalid Request Authenticator length")
	}
	if len(salt) != 2 {
		return nil, errors.New("eapaka: invalid MPPE Salt length")
	}

	// 2. Prepare Plaintext
	// Structure: [Length(1)] + [Key] + [Padding]
	// RFC 2548: "The length of the ... length + key + padding must be a multiple of 16"
	// Note: RFC says "salt + length + key + padding", but the salt is NOT encrypted.
	// The encrypted portion P is [Length + Key + Padding].

	plainLen := 1 + len(key)

	// Calculate padding needed to make P a multiple of 16
	padLen := (16 - (plainLen % 16)) % 16

	// Construct buffer
	plaintext := make([]byte, plainLen+padLen)
	plaintext[0] = byte(len(key))
	copy(plaintext[1:], key)
	// Padding is zero-valued by make()

	// 3. Encrypt
	// Result buffer: [Salt(2)] + [Encrypted Blocks...]
	result := make([]byte, 2+len(plaintext))
	copy(result[0:2], salt)

	h := md5.New()

	// b(1) = MD5(Secret + RequestAuthenticator + Salt)
	h.Write(secret)
	h.Write(reqAuth)
	h.Write(salt)
	b := h.Sum(nil) // 16 bytes

	// c(i) = p(i) ^ b(i)
	// Encrypted blocks start at offset 2 in result

	for i := 0; i < len(plaintext); i += 16 {
		pBlock := plaintext[i : i+16]
		cBlock := result[2+i : 2+i+16] // Write directly to result

		for j := 0; j < 16; j++ {
			cBlock[j] = pBlock[j] ^ b[j]
		}

		// Prepare b(i+1) = MD5(Secret + c(i))
		h.Reset()
		h.Write(secret)
		h.Write(cBlock) // Use the ciphertext of the current block
		b = h.Sum(nil)
	}

	return result, nil
}

// DecryptMPPEKey decrypts the value of an MS-MPPE-Send-Key or MS-MPPE-Recv-Key
// attribute and returns the key. It is the inverse of EncryptMPPEKey.
//
// Ref: RFC 2548 Section 2.4.2 and 2.4.3
// enc: The attribute value: the Salt (2 bytes) followed by the encrypted String.
// secret: The RADIUS shared secret.
// reqAuth: The Request Authenticator from the corresponding Access-Request packet (16 bytes).
//
// The encrypted String must be a positive multiple of 16 bytes, and the
// decrypted Key-Length must be at least 1 and must not exceed the decrypted
// data. DecryptMPPEKey does not check the Salt (that its most significant bit
// is set and that it is unique within the Access-Accept) or the padding bytes;
// callers can inspect enc[0:2] themselves.
func DecryptMPPEKey(enc, secret, reqAuth []byte) ([]byte, error) {
	if len(reqAuth) != 16 {
		return nil, errors.New("eapaka: invalid Request Authenticator length")
	}
	if len(enc) < 2+16 || (len(enc)-2)%16 != 0 {
		return nil, wrapErrorf(ErrMalformedMPPEKey, "eapaka: invalid MPPE key attribute length %d (want the Salt and a positive multiple of 16 bytes)", len(enc))
	}
	salt, ciphertext := enc[:2], enc[2:]

	// b(1) = MD5(S + R + A)、b(i) = MD5(S + c(i-1))、p(i) = c(i) xor b(i)
	plain := make([]byte, 0, len(ciphertext))
	prev := slices.Concat(reqAuth, salt)
	h := md5.New()
	for block := range slices.Chunk(ciphertext, md5.Size) {
		h.Reset()
		h.Write(secret)
		h.Write(prev)
		b := h.Sum(nil)
		for j, c := range block {
			plain = append(plain, c^b[j])
		}
		prev = block
	}

	// P = Key-Length（1 バイト）| Key | Padding
	keyLen := int(plain[0])
	if keyLen == 0 || keyLen > len(plain)-1 {
		return nil, wrapErrorf(ErrMalformedMPPEKey, "eapaka: invalid MPPE Key-Length %d for %d bytes of decrypted data", keyLen, len(plain))
	}
	return plain[1 : 1+keyLen], nil
}
