/*
 * mppecheck: pyvectors.py が作った MPPE 鍵のベクタを、hostap の RADIUS 実装
 * （src/radius/radius.c の encrypt_ms_key / decrypt_ms_key）で照合する。
 *
 * 2 つの関数は radius.c の static 関数なので、radius.c をそのまま取り込む。
 *
 * 使い方: mppecheck <secret> <req_auth> <salt> <key> <encrypted>（すべて 16 進）
 * 終了コード: 0 = 一致、1 = 不一致、2 = 引数の誤り
 */

#include "radius/radius.c"

static size_t arg_hex(const char *hex, u8 *buf, size_t size)
{
	size_t len = os_strlen(hex) / 2;

	if (os_strlen(hex) % 2 || len > size || hexstr2bin(hex, buf, len) < 0) {
		fprintf(stderr, "mppecheck: invalid hex: %s\n", hex);
		exit(2);
	}
	return len;
}

int main(int argc, char *argv[])
{
	u8 secret[256], req_auth[MD5_MAC_LEN], salt[2], key[255];
	u8 encrypted[2 + 256], ebuf[256], *dec;
	size_t secret_len, key_len, enc_len, elen = 0, dlen = 0;

	if (argc != 6) {
		fprintf(stderr, "usage: %s <secret> <req_auth> <salt> <key> "
			"<encrypted>\n", argv[0]);
		return 2;
	}
	secret_len = arg_hex(argv[1], secret, sizeof(secret));
	if (arg_hex(argv[2], req_auth, sizeof(req_auth)) != sizeof(req_auth) ||
	    arg_hex(argv[3], salt, sizeof(salt)) != sizeof(salt)) {
		fprintf(stderr, "mppecheck: bad req_auth or salt length\n");
		return 2;
	}
	key_len = arg_hex(argv[4], key, sizeof(key));
	enc_len = arg_hex(argv[5], encrypted, sizeof(encrypted));

	/* 暗号化: encrypt_ms_key() の出力は Salt を含まない */
	if (encrypt_ms_key(key, key_len, WPA_GET_BE16(salt), req_auth, secret,
			   secret_len, ebuf, &elen) < 0) {
		fprintf(stderr, "mppecheck: encrypt_ms_key failed\n");
		return 1;
	}
	if (enc_len != 2 + elen || os_memcmp(encrypted, salt, 2) != 0 ||
	    os_memcmp(encrypted + 2, ebuf, elen) != 0) {
		fprintf(stderr, "mppecheck: encrypt_ms_key mismatch\n");
		return 1;
	}

	/* 復号: decrypt_ms_key() は Salt を含む値を受け取る */
	dec = decrypt_ms_key(encrypted, enc_len, req_auth, secret, secret_len,
			     &dlen);
	if (!dec || dlen != key_len || os_memcmp(dec, key, key_len) != 0) {
		fprintf(stderr, "mppecheck: decrypt_ms_key mismatch\n");
		os_free(dec);
		return 1;
	}
	os_free(dec);
	return 0;
}
