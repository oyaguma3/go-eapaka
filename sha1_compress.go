package eapaka

// SHA-1圧縮関数の自前実装
// Go標準ライブラリの crypto/sha1 は圧縮関数をエクスポートしていないため、
// FIPS 186-2 G関数の実装のために blockGeneric ロジックを移植する。
// 参照: Go標準ライブラリ crypto/sha1/sha1block.go

import (
	"encoding/binary"
	"math/bits"
)

// SHA-1定数
const (
	sha1K0    = 0x5A827999
	sha1K1    = 0x6ED9EBA1
	sha1K2    = 0x8F1BBCDC
	sha1K3    = 0xCA62C1D6
	sha1Chunk = 64
)

// SHA-1初期ハッシュ値（FIPS 180-4）
var sha1InitH = [5]uint32{
	0x67452301,
	0xEFCDAB89,
	0x98BADCFE,
	0x10325476,
	0xC3D2E1F0,
}

// sha1Compress はSHA-1圧縮関数を直接実行する（パディングなし）。
// FIPS 186-2 の G(t, c) 関数として使用。
// state: 入力ハッシュ状態（5×uint32）。関数内で更新される。
// block: 64バイトのデータブロック。
func sha1Compress(state *[5]uint32, block []byte) {
	if len(block) < sha1Chunk {
		panic("sha1Compress: block must be at least 64 bytes")
	}

	var w [16]uint32

	h0, h1, h2, h3, h4 := state[0], state[1], state[2], state[3], state[4]

	// メッセージスケジュール配列の初期化
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = uint32(block[j])<<24 | uint32(block[j+1])<<16 | uint32(block[j+2])<<8 | uint32(block[j+3])
	}

	a, b, c, d, e := h0, h1, h2, h3, h4

	// ラウンド1: i = 0..19
	i := 0
	for ; i < 16; i++ {
		f := b&c | (^b)&d
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K0
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}
	for ; i < 20; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[i&0xf]
		w[i&0xf] = bits.RotateLeft32(tmp, 1)
		f := b&c | (^b)&d
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K0
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}
	// ラウンド2: i = 20..39
	for ; i < 40; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[i&0xf]
		w[i&0xf] = bits.RotateLeft32(tmp, 1)
		f := b ^ c ^ d
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K1
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}
	// ラウンド3: i = 40..59
	for ; i < 60; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[i&0xf]
		w[i&0xf] = bits.RotateLeft32(tmp, 1)
		f := ((b | c) & d) | (b & c)
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K2
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}
	// ラウンド4: i = 60..79
	for ; i < 80; i++ {
		tmp := w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[i&0xf]
		w[i&0xf] = bits.RotateLeft32(tmp, 1)
		f := b ^ c ^ d
		t := bits.RotateLeft32(a, 5) + f + e + w[i&0xf] + sha1K3
		a, b, c, d, e = t, a, bits.RotateLeft32(b, 30), c, d
	}

	// 圧縮関数の出力 = 入力状態 + 作業変数
	state[0] = h0 + a
	state[1] = h1 + b
	state[2] = h2 + c
	state[3] = h3 + d
	state[4] = h4 + e
}

// sha1CompressToBytes はsha1Compressの結果を20バイトのスライスとして返す。
// state は変更されない（コピーを使用）。
func sha1CompressToBytes(state [5]uint32, block []byte) []byte {
	s := state // コピー
	sha1Compress(&s, block)
	out := make([]byte, 20)
	binary.BigEndian.PutUint32(out[0:4], s[0])
	binary.BigEndian.PutUint32(out[4:8], s[1])
	binary.BigEndian.PutUint32(out[8:12], s[2])
	binary.BigEndian.PutUint32(out[12:16], s[3])
	binary.BigEndian.PutUint32(out[16:20], s[4])
	return out
}
