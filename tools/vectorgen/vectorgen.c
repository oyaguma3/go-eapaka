/*
 * vectorgen: go-eapaka のテストベクタを hostap から生成する。
 *
 * hostap（hostapd / wpa_supplicant）の EAP-SIM/AKA/AKA' 共通ルーチン
 * （src/eap_common/eap_sim_common.c）と、hostap 内蔵の暗号実装にリンクし、
 * 鍵導出・AT_ENCR_DATA・MAC の値を JSON に書き出す。go-eapaka とは独立した
 * 実装から作った値で go-eapaka を検証するのが目的。
 *
 * 使い方: vectorgen <出力ディレクトリ>
 *
 * ビルド方法と各ファイルの内容は README.md を参照。
 */

#include "includes.h"

#include "common.h"
#include "wpabuf.h"
#include "crypto/crypto.h"
#include "crypto/random.h"
#include "crypto/sha1.h"
#include "eap_common/eap_defs.h"
#include "eap_common/eap_sim_common.h"

#ifndef HOSTAP_DESC
#error "HOSTAP_DESC must be defined (see Makefile)"
#endif

#define GENERATOR "tools/vectorgen/vectorgen.c"

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "vectorgen: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

/* 16 進文字列を buf に変換する。長さが len バイトでなければ終了する。 */
static void unhex(const char *hex, u8 *buf, size_t len)
{
	if (os_strlen(hex) != len * 2 || hexstr2bin(hex, buf, len) < 0)
		die("invalid hex (want %zu bytes): %s", len, hex);
}

/* -------------------------------------------------------------------------
 * IV の固定
 *
 * eap_sim_msg_add_encr_start() は random_get_bytes() で AT_IV を作る。
 * ベクタを再現できるよう、random.c はリンクせずにこの関数を定義し、
 * 直前に set_iv() で指定した値を返す。IV の使い回しを防ぐため 1 回で無効化する。
 * ------------------------------------------------------------------------- */

static u8 next_iv[EAP_SIM_IV_LEN];
static int next_iv_set;

static void set_iv(const u8 *iv)
{
	os_memcpy(next_iv, iv, EAP_SIM_IV_LEN);
	next_iv_set = 1;
}

int random_get_bytes(void *buf, size_t len)
{
	if (!next_iv_set || len != EAP_SIM_IV_LEN)
		die("unexpected random_get_bytes(len=%zu)", len);
	os_memcpy(buf, next_iv, len);
	next_iv_set = 0;
	return 0;
}

/* -------------------------------------------------------------------------
 * JSON の書き出し（Python の json.dump(indent=2) と同じ形）
 * ------------------------------------------------------------------------- */

struct jw {
	FILE *f;
	char path[1024];
	int ncase;
	int nfield;
};

static void jw_raw_str(FILE *f, const char *s)
{
	fputc('"', f);
	for (; *s; s++) {
		unsigned char c = (unsigned char) *s;

		if (c == '"' || c == '\\')
			fprintf(f, "\\%c", c);
		else if (c < 0x20 || c > 0x7e)
			die("non-printable character in JSON string");
		else
			fputc(c, f);
	}
	fputc('"', f);
}

static void jw_open(struct jw *w, const char *dir, const char *file,
		    const char *source)
{
	os_memset(w, 0, sizeof(*w));
	if (os_snprintf_error(sizeof(w->path),
			      os_snprintf(w->path, sizeof(w->path), "%s/%s",
					  dir, file)))
		die("path too long");
	w->f = fopen(w->path, "w");
	if (!w->f)
		die("cannot open %s", w->path);
	fprintf(w->f, "{\n  \"source\": ");
	jw_raw_str(w->f, source);
	fprintf(w->f, ",\n  \"generator\": ");
	jw_raw_str(w->f, GENERATOR);
	fprintf(w->f, ",\n  \"cases\": [");
}

static void jw_key(struct jw *w, const char *key)
{
	fprintf(w->f, "%s\n      ", w->nfield++ ? "," : "");
	jw_raw_str(w->f, key);
	fprintf(w->f, ": ");
}

static void jw_case_begin(struct jw *w, const char *name)
{
	fprintf(w->f, "%s\n    {", w->ncase++ ? "," : "");
	w->nfield = 0;
	jw_key(w, "name");
	jw_raw_str(w->f, name);
}

static void jw_str(struct jw *w, const char *key, const char *s)
{
	jw_key(w, key);
	jw_raw_str(w->f, s);
}

static void jw_int(struct jw *w, const char *key, long v)
{
	jw_key(w, key);
	fprintf(w->f, "%ld", v);
}

static void jw_hex(struct jw *w, const char *key, const u8 *b, size_t len)
{
	size_t i;

	jw_key(w, key);
	fputc('"', w->f);
	for (i = 0; i < len; i++)
		fprintf(w->f, "%02x", b[i]);
	fputc('"', w->f);
}

static void jw_case_end(struct jw *w)
{
	fprintf(w->f, "\n    }");
}

static void jw_close(struct jw *w)
{
	fprintf(w->f, "\n  ]\n}\n");
	if (fclose(w->f) != 0)
		die("cannot write %s", w->path);
	printf("wrote %s (%d cases)\n", w->path, w->ncase);
}

/* -------------------------------------------------------------------------
 * 共通の入力値
 * ------------------------------------------------------------------------- */

/* RFC 9048 付録 D のケース 1 */
#define RFC9048_C1_IDENTITY "0555444333222111"
#define RFC9048_C1_NETNAME "WLAN"
#define RFC9048_C1_AUTN "bb52e91c747ac3ab2a5c23d15ee351d5"
#define RFC9048_C1_IK "9744871ad32bf9bbd1dd5ce54e3e2e5a"
#define RFC9048_C1_CK "5349fbe098649f948f5d2e973a81c00f"
#define RFC9048_C1_CK_PRIME "0093962d0dd84aa5684b045c9edffa04"
#define RFC9048_C1_IK_PRIME "ccfc230ca74fcc96c0a5d61164f5a76c"
#define RFC9048_C1_K_ENCR "766fa0a6c317174b812d52fbcd11a179"
#define RFC9048_C1_K_RE \
	"cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a"
#define RFC9048_C1_MSK \
	"67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544" \
	"e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a"

/* 64 バイトを超える ID（SHA-1/SHA-256 の複数ブロックを通す） */
#define LONG_IDENTITY \
	"4000000000000000000000000000000000000000000000000000000000000000" \
	"0000000000000001@wlan.mnc001.mcc001.3gppnetwork.org"

/* 鍵導出で得た値。後のパケットの生成に使う。 */
static u8 aka1_k_encr[EAP_SIM_K_ENCR_LEN];
static u8 aka1_k_aut[EAP_SIM_K_AUT_LEN];
static u8 aka1_mk[EAP_SIM_MK_LEN];
static u8 akap1_k_encr[EAP_SIM_K_ENCR_LEN];
static u8 akap1_k_aut[EAP_AKA_PRIME_K_AUT_LEN];
static u8 akap1_k_re[EAP_AKA_PRIME_K_RE_LEN];

/* -------------------------------------------------------------------------
 * 自己検証: RFC 9048 付録 D のケース 1 と一致すること
 *
 * リンクした hostap と内蔵暗号の組み合わせが正しく動いていることを、
 * ベクタを書き出す前に確かめる。
 * ------------------------------------------------------------------------- */

static void selftest_rfc9048(void)
{
	u8 ck[EAP_AKA_CK_LEN], ik[EAP_AKA_IK_LEN], autn[EAP_AKA_AUTN_LEN];
	u8 k_encr[EAP_SIM_K_ENCR_LEN], k_aut[EAP_AKA_PRIME_K_AUT_LEN];
	u8 k_re[EAP_AKA_PRIME_K_RE_LEN], msk[EAP_MSK_LEN], emsk[EAP_EMSK_LEN];
	u8 want[EAP_MSK_LEN];

	unhex(RFC9048_C1_CK, ck, sizeof(ck));
	unhex(RFC9048_C1_IK, ik, sizeof(ik));
	unhex(RFC9048_C1_AUTN, autn, sizeof(autn));
	eap_aka_prime_derive_ck_ik_prime(ck, ik, autn,
					 (const u8 *) RFC9048_C1_NETNAME,
					 os_strlen(RFC9048_C1_NETNAME));
	unhex(RFC9048_C1_CK_PRIME, want, EAP_AKA_CK_LEN);
	if (os_memcmp(ck, want, EAP_AKA_CK_LEN) != 0)
		die("self-test failed: RFC 9048 case 1 CK'");
	unhex(RFC9048_C1_IK_PRIME, want, EAP_AKA_IK_LEN);
	if (os_memcmp(ik, want, EAP_AKA_IK_LEN) != 0)
		die("self-test failed: RFC 9048 case 1 IK'");

	eap_aka_prime_derive_keys((const u8 *) RFC9048_C1_IDENTITY,
				  os_strlen(RFC9048_C1_IDENTITY), ik, ck,
				  k_encr, k_aut, k_re, msk, emsk);
	unhex(RFC9048_C1_K_ENCR, want, EAP_SIM_K_ENCR_LEN);
	if (os_memcmp(k_encr, want, EAP_SIM_K_ENCR_LEN) != 0)
		die("self-test failed: RFC 9048 case 1 K_encr");
	unhex(RFC9048_C1_K_RE, want, EAP_AKA_PRIME_K_RE_LEN);
	if (os_memcmp(k_re, want, EAP_AKA_PRIME_K_RE_LEN) != 0)
		die("self-test failed: RFC 9048 case 1 K_re");
	unhex(RFC9048_C1_MSK, want, EAP_MSK_LEN);
	if (os_memcmp(msk, want, EAP_MSK_LEN) != 0)
		die("self-test failed: RFC 9048 case 1 MSK");
}

/* -------------------------------------------------------------------------
 * aka_keys.json: EAP-AKA のフル認証の鍵導出（RFC 4187 §7）
 * ------------------------------------------------------------------------- */

struct aka_full_input {
	const char *name;
	const char *identity;
	const char *ik;
	const char *ck;
};

static const struct aka_full_input aka_full_inputs[] = {
	{ "aka_full_1", RFC9048_C1_IDENTITY, RFC9048_C1_IK, RFC9048_C1_CK },
	{ "aka_full_nai",
	  "0123456789012345@wlan.mnc001.mcc001.3gppnetwork.org",
	  "000102030405060708090a0b0c0d0e0f",
	  "101112131415161718191a1b1c1d1e1f" },
	/* kdf_test.go の既存のテスト（test_identity、CK=IK=0）と同じ入力 */
	{ "aka_full_zero_keys", "test_identity",
	  "00000000000000000000000000000000",
	  "00000000000000000000000000000000" },
	{ "aka_full_pseudonym", "2s7ah6n9q3fc8w4x",
	  "ffeeddccbbaa99887766554433221100",
	  "f0e1d2c3b4a5968778695a4b3c2d1e0f" },
	{ "aka_full_long_identity", LONG_IDENTITY,
	  "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
	  "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a" },
};

static void gen_aka_keys(const char *dir)
{
	struct jw w;
	size_t i;

	jw_open(&w, dir, "aka_keys.json",
		"hostap " HOSTAP_DESC ": eap_aka_derive_mk, eap_sim_derive_keys");
	for (i = 0; i < ARRAY_SIZE(aka_full_inputs); i++) {
		const struct aka_full_input *in = &aka_full_inputs[i];
		u8 ik[EAP_AKA_IK_LEN], ck[EAP_AKA_CK_LEN], mk[EAP_SIM_MK_LEN];
		u8 k_encr[EAP_SIM_K_ENCR_LEN], k_aut[EAP_SIM_K_AUT_LEN];
		u8 msk[EAP_SIM_KEYING_DATA_LEN], emsk[EAP_EMSK_LEN];

		unhex(in->ik, ik, sizeof(ik));
		unhex(in->ck, ck, sizeof(ck));
		eap_aka_derive_mk((const u8 *) in->identity,
				  os_strlen(in->identity), ik, ck, mk);
		if (eap_sim_derive_keys(mk, k_encr, k_aut, msk, emsk) < 0)
			die("eap_sim_derive_keys failed");

		if (i == 0) {
			os_memcpy(aka1_k_encr, k_encr, sizeof(k_encr));
			os_memcpy(aka1_k_aut, k_aut, sizeof(k_aut));
			os_memcpy(aka1_mk, mk, sizeof(mk));
		}

		jw_case_begin(&w, in->name);
		jw_str(&w, "identity", in->identity);
		jw_hex(&w, "ik", ik, sizeof(ik));
		jw_hex(&w, "ck", ck, sizeof(ck));
		jw_hex(&w, "mk", mk, sizeof(mk));
		jw_hex(&w, "k_encr", k_encr, sizeof(k_encr));
		jw_hex(&w, "k_aut", k_aut, sizeof(k_aut));
		jw_hex(&w, "msk", msk, sizeof(msk));
		jw_hex(&w, "emsk", emsk, sizeof(emsk));
		jw_case_end(&w);
	}
	jw_close(&w);
}

/* -------------------------------------------------------------------------
 * aka_prime_keys.json: EAP-AKA' のフル認証の鍵導出（RFC 9048 §3.3）
 * ------------------------------------------------------------------------- */

struct aka_prime_full_input {
	const char *name;
	const char *identity;
	const char *network_name;
	const char *autn;
	const char *ik;
	const char *ck;
};

static const struct aka_prime_full_input aka_prime_full_inputs[] = {
	{ "aka_prime_full_rfc9048_case1", RFC9048_C1_IDENTITY,
	  RFC9048_C1_NETNAME, RFC9048_C1_AUTN, RFC9048_C1_IK, RFC9048_C1_CK },
	{ "aka_prime_full_nai",
	  "6555444333222111@wlan.mnc001.mcc001.3gppnetwork.org", "WLAN",
	  "000102030405060708090a0b0c0d0e0f",
	  "202122232425262728292a2b2c2d2e2f",
	  "303132333435363738393a3b3c3d3e3f" },
	{ "aka_prime_full_5g_network_name", "0555444333222111",
	  "5G:mnc001.mcc001.3gppnetwork.org",
	  "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
	  "404142434445464748494a4b4c4d4e4f",
	  "505152535455565758595a5b5c5d5e5f" },
	{ "aka_prime_full_long_identity", LONG_IDENTITY, "WLAN",
	  "ffffffffffff00000000000000000000",
	  "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
	  "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a" },
};

static void gen_aka_prime_keys(const char *dir)
{
	struct jw w;
	size_t i;

	jw_open(&w, dir, "aka_prime_keys.json",
		"hostap " HOSTAP_DESC ": eap_aka_prime_derive_ck_ik_prime, "
		"eap_aka_prime_derive_keys");
	for (i = 0; i < ARRAY_SIZE(aka_prime_full_inputs); i++) {
		const struct aka_prime_full_input *in =
			&aka_prime_full_inputs[i];
		u8 autn[EAP_AKA_AUTN_LEN], ik[EAP_AKA_IK_LEN];
		u8 ck[EAP_AKA_CK_LEN], ik_prime[EAP_AKA_IK_LEN];
		u8 ck_prime[EAP_AKA_CK_LEN];
		u8 k_encr[EAP_SIM_K_ENCR_LEN], k_aut[EAP_AKA_PRIME_K_AUT_LEN];
		u8 k_re[EAP_AKA_PRIME_K_RE_LEN], msk[EAP_MSK_LEN];
		u8 emsk[EAP_EMSK_LEN];

		unhex(in->autn, autn, sizeof(autn));
		unhex(in->ik, ik, sizeof(ik));
		unhex(in->ck, ck, sizeof(ck));
		os_memcpy(ik_prime, ik, sizeof(ik));
		os_memcpy(ck_prime, ck, sizeof(ck));
		/* SQN xor AK は AUTN の先頭 6 バイト */
		eap_aka_prime_derive_ck_ik_prime(ck_prime, ik_prime, autn,
						 (const u8 *) in->network_name,
						 os_strlen(in->network_name));
		eap_aka_prime_derive_keys((const u8 *) in->identity,
					  os_strlen(in->identity), ik_prime,
					  ck_prime, k_encr, k_aut, k_re, msk,
					  emsk);

		if (i == 0) {
			os_memcpy(akap1_k_encr, k_encr, sizeof(k_encr));
			os_memcpy(akap1_k_aut, k_aut, sizeof(k_aut));
			os_memcpy(akap1_k_re, k_re, sizeof(k_re));
		}

		jw_case_begin(&w, in->name);
		jw_str(&w, "identity", in->identity);
		jw_str(&w, "network_name", in->network_name);
		jw_hex(&w, "autn", autn, sizeof(autn));
		jw_hex(&w, "ik", ik, sizeof(ik));
		jw_hex(&w, "ck", ck, sizeof(ck));
		jw_hex(&w, "ik_prime", ik_prime, sizeof(ik_prime));
		jw_hex(&w, "ck_prime", ck_prime, sizeof(ck_prime));
		jw_hex(&w, "k_encr", k_encr, sizeof(k_encr));
		jw_hex(&w, "k_aut", k_aut, sizeof(k_aut));
		jw_hex(&w, "k_re", k_re, sizeof(k_re));
		jw_hex(&w, "msk", msk, sizeof(msk));
		jw_hex(&w, "emsk", emsk, sizeof(emsk));
		jw_case_end(&w);
	}
	jw_close(&w);
}

/* -------------------------------------------------------------------------
 * reauth_keys_aka.json / reauth_keys_aka_prime.json: 再認証の鍵導出
 * （RFC 4187 §7、RFC 9048 §3.3）
 * ------------------------------------------------------------------------- */

struct reauth_input {
	const char *name;
	const char *identity;
	u16 counter;
	const char *nonce_s;
	const char *key; /* AKA は MK（20 バイト）、AKA' は K_re（32 バイト）。NULL ならフル認証の値 */
};

static const struct reauth_input reauth_aka_inputs[] = {
	/* aka_full_1 の MK を使う */
	{ "aka_reauth_counter1",
	  "4a1b2c3d4e5f6071@wlan.mnc001.mcc001.3gppnetwork.org", 1,
	  "000102030405060708090a0b0c0d0e0f", NULL },
	{ "aka_reauth_counter2",
	  "4a1b2c3d4e5f6072@wlan.mnc001.mcc001.3gppnetwork.org", 2,
	  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", NULL },
	{ "aka_reauth_counter_max", "r", 0xffff,
	  "0123456789abcdef0123456789abcdef",
	  "00112233445566778899aabbccddeeff00112233" },
	{ "aka_reauth_long_identity", LONG_IDENTITY, 0x0100,
	  "deadbeefdeadbeefdeadbeefdeadbeef",
	  "ffffffffffffffffffffffffffffffffffffffff" },
};

static const struct reauth_input reauth_aka_prime_inputs[] = {
	/* aka_prime_full_rfc9048_case1 の K_re を使う */
	{ "aka_prime_reauth_counter1",
	  "8a1b2c3d4e5f6071@wlan.mnc001.mcc001.3gppnetwork.org", 1,
	  "000102030405060708090a0b0c0d0e0f", NULL },
	{ "aka_prime_reauth_counter2",
	  "8a1b2c3d4e5f6072@wlan.mnc001.mcc001.3gppnetwork.org", 2,
	  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", NULL },
	{ "aka_prime_reauth_counter_max", "r", 0xffff,
	  "0123456789abcdef0123456789abcdef",
	  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" },
	{ "aka_prime_reauth_long_identity", LONG_IDENTITY, 0x0100,
	  "deadbeefdeadbeefdeadbeefdeadbeef",
	  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
};

static void gen_reauth_keys_aka(const char *dir)
{
	struct jw w;
	size_t i;

	jw_open(&w, dir, "reauth_keys_aka.json",
		"hostap " HOSTAP_DESC ": eap_sim_derive_keys_reauth");
	for (i = 0; i < ARRAY_SIZE(reauth_aka_inputs); i++) {
		const struct reauth_input *in = &reauth_aka_inputs[i];
		u8 nonce_s[EAP_SIM_NONCE_S_LEN], mk[EAP_SIM_MK_LEN];
		u8 counter[2], xkey[SHA1_MAC_LEN];
		u8 msk[EAP_SIM_KEYING_DATA_LEN], emsk[EAP_EMSK_LEN];
		const u8 *addr[4];
		size_t len[4];

		unhex(in->nonce_s, nonce_s, sizeof(nonce_s));
		if (in->key)
			unhex(in->key, mk, sizeof(mk));
		else
			os_memcpy(mk, aka1_mk, sizeof(mk));
		if (eap_sim_derive_keys_reauth(in->counter,
					       (const u8 *) in->identity,
					       os_strlen(in->identity),
					       nonce_s, mk, msk, emsk) < 0)
			die("eap_sim_derive_keys_reauth failed");

		/*
		 * 中間値の XKEY' = SHA1(Identity|counter|NONCE_S|MK)。
		 * hostap はこの値を返さないので、eap_sim_derive_keys_reauth() と
		 * 同じ組み立てを hostap の sha1_vector() で計算する。
		 */
		WPA_PUT_BE16(counter, in->counter);
		addr[0] = (const u8 *) in->identity;
		len[0] = os_strlen(in->identity);
		addr[1] = counter;
		len[1] = sizeof(counter);
		addr[2] = nonce_s;
		len[2] = sizeof(nonce_s);
		addr[3] = mk;
		len[3] = sizeof(mk);
		if (sha1_vector(4, addr, len, xkey) < 0)
			die("sha1_vector failed");

		jw_case_begin(&w, in->name);
		jw_str(&w, "identity", in->identity);
		jw_int(&w, "counter", in->counter);
		jw_hex(&w, "nonce_s", nonce_s, sizeof(nonce_s));
		jw_hex(&w, "mk", mk, sizeof(mk));
		jw_hex(&w, "xkey_prime", xkey, sizeof(xkey));
		jw_hex(&w, "msk", msk, sizeof(msk));
		jw_hex(&w, "emsk", emsk, sizeof(emsk));
		jw_case_end(&w);
	}
	jw_close(&w);
}

static void gen_reauth_keys_aka_prime(const char *dir)
{
	struct jw w;
	size_t i;

	jw_open(&w, dir, "reauth_keys_aka_prime.json",
		"hostap " HOSTAP_DESC ": eap_aka_prime_derive_keys_reauth");
	for (i = 0; i < ARRAY_SIZE(reauth_aka_prime_inputs); i++) {
		const struct reauth_input *in = &reauth_aka_prime_inputs[i];
		u8 nonce_s[EAP_SIM_NONCE_S_LEN], k_re[EAP_AKA_PRIME_K_RE_LEN];
		u8 msk[EAP_MSK_LEN], emsk[EAP_EMSK_LEN];

		unhex(in->nonce_s, nonce_s, sizeof(nonce_s));
		if (in->key)
			unhex(in->key, k_re, sizeof(k_re));
		else
			os_memcpy(k_re, akap1_k_re, sizeof(k_re));
		if (eap_aka_prime_derive_keys_reauth(k_re, in->counter,
						     (const u8 *) in->identity,
						     os_strlen(in->identity),
						     nonce_s, msk, emsk) < 0)
			die("eap_aka_prime_derive_keys_reauth failed");

		jw_case_begin(&w, in->name);
		jw_str(&w, "identity", in->identity);
		jw_int(&w, "counter", in->counter);
		jw_hex(&w, "nonce_s", nonce_s, sizeof(nonce_s));
		jw_hex(&w, "k_re", k_re, sizeof(k_re));
		jw_hex(&w, "msk", msk, sizeof(msk));
		jw_hex(&w, "emsk", emsk, sizeof(emsk));
		jw_case_end(&w);
	}
	jw_close(&w);
}

/* -------------------------------------------------------------------------
 * パケットの組み立てと検証
 * ------------------------------------------------------------------------- */

/* EAP ヘッダ（4）＋ Type・Subtype・Reserved（4） */
#define AKA_HDR_LEN 8

static int aka_param(int method)
{
	/* eap_sim_parse_attr() の aka 引数: 1 = EAP-AKA、2 = EAP-AKA' */
	return method == EAP_TYPE_AKA_PRIME ? 2 : 1;
}

static void parse_packet(const struct wpabuf *buf, int method,
			 struct eap_sim_attrs *attr)
{
	const u8 *pos = wpabuf_head_u8(buf);

	if (wpabuf_len(buf) < AKA_HDR_LEN ||
	    WPA_GET_BE16(pos + 2) != wpabuf_len(buf))
		die("bad packet length");
	if (eap_sim_parse_attr(pos + AKA_HDR_LEN, pos + wpabuf_len(buf), attr,
			       aka_param(method), 0) < 0)
		die("eap_sim_parse_attr failed");
}

/* MAC を hostap で検証する。0 = 一致、それ以外 = 不一致 */
static int verify_mac(int method, const u8 *k_aut, const struct wpabuf *buf,
		      const u8 *mac, const u8 *extra, size_t extra_len)
{
	if (method == EAP_TYPE_AKA_PRIME)
		return eap_sim_verify_mac_sha256(k_aut, buf, mac, extra,
						 extra_len);
	return eap_sim_verify_mac(k_aut, buf, mac, extra, extra_len);
}

/*
 * AT_ENCR_DATA を hostap で復号・解析し、復号結果（AT_PADDING を含む平文）を
 * 返す。呼び出し側が os_free() する。
 */
static u8 *decrypt_encr(int method, const u8 *k_encr,
			const struct eap_sim_attrs *attr)
{
	struct eap_sim_attrs eattr;
	u8 *plain;

	if (!attr->iv || !attr->encr_data)
		die("AT_IV or AT_ENCR_DATA missing");
	plain = eap_sim_parse_encr(k_encr, attr->encr_data,
				   attr->encr_data_len, attr->iv, &eattr,
				   aka_param(method));
	if (!plain)
		die("eap_sim_parse_encr failed");
	return plain;
}

/* 平文の末尾にある AT_PADDING の長さ（属性全体のバイト数）を返す */
static size_t padding_len(const u8 *plain, size_t len)
{
	size_t pos = 0, last = 0;
	u8 last_type = 0;

	while (pos < len) {
		size_t alen;

		if (pos + 2 > len || plain[pos + 1] == 0)
			die("bad attribute in plaintext");
		alen = plain[pos + 1] * 4;
		if (pos + alen > len)
			die("attribute overflow in plaintext");
		last = alen;
		last_type = plain[pos];
		pos += alen;
	}
	return last_type == EAP_SIM_AT_PADDING ? last : 0;
}

/* -------------------------------------------------------------------------
 * encr_data.json: AT_ENCR_DATA の暗号化（RFC 4187 §10.12）
 * ------------------------------------------------------------------------- */

static const char *encr_k_encr = "000102030405060708090a0b0c0d0e0f";

static void add_counter(struct eap_sim_msg *msg, u16 counter)
{
	eap_sim_msg_add(msg, EAP_SIM_AT_COUNTER, counter, NULL, 0);
}

static void add_nonce_s(struct eap_sim_msg *msg, const u8 *nonce_s)
{
	eap_sim_msg_add(msg, EAP_SIM_AT_NONCE_S, 0, nonce_s,
			EAP_SIM_NONCE_S_LEN);
}

static void add_id_attr(struct eap_sim_msg *msg, u8 type, const char *id)
{
	size_t len = os_strlen(id);

	eap_sim_msg_add(msg, type, len, (const u8 *) id, len);
}

enum encr_kind {
	ENCR_COUNTER,		  /* 4 バイト → パディング 12 */
	ENCR_COUNTER_NONCE,	  /* 24 バイト → パディング 8 */
	ENCR_PSEUDONYM,		  /* 12 バイト → パディング 4 */
	ENCR_COUNTER_NONCE_REAUTH, /* 48 バイト → パディングなし */
	ENCR_COUNTER_TOO_SMALL,	  /* 8 バイト → パディング 8 */
	ENCR_PSEUDONYM_REAUTH,	  /* 160 バイト（複数ブロック）→ パディングなし */
};

struct encr_input {
	const char *name;
	enum encr_kind kind;
	size_t want_pad; /* 期待する AT_PADDING 全体のバイト数 */
	const char *iv;
};

static const struct encr_input encr_inputs[] = {
	{ "encr_counter_pad12", ENCR_COUNTER, 12,
	  "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" },
	{ "encr_counter_nonce_pad8", ENCR_COUNTER_NONCE, 8,
	  "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" },
	{ "encr_pseudonym_pad4", ENCR_PSEUDONYM, 4,
	  "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" },
	{ "encr_counter_nonce_reauth_nopad", ENCR_COUNTER_NONCE_REAUTH, 0,
	  "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" },
	{ "encr_counter_too_small_pad8", ENCR_COUNTER_TOO_SMALL, 8,
	  "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" },
	{ "encr_pseudonym_reauth_multiblock", ENCR_PSEUDONYM_REAUTH, 0,
	  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" },
};

static const char *nonce_s_hex = "0f0e0d0c0b0a09080706050403020100";

static void gen_encr_data(const char *dir)
{
	struct jw w;
	size_t i;
	int seen_pad[4] = { 0, 0, 0, 0 };
	u8 k_encr[EAP_SIM_K_ENCR_LEN], nonce_s[EAP_SIM_NONCE_S_LEN];

	unhex(encr_k_encr, k_encr, sizeof(k_encr));
	unhex(nonce_s_hex, nonce_s, sizeof(nonce_s));

	jw_open(&w, dir, "encr_data.json",
		"hostap " HOSTAP_DESC ": eap_sim_msg_add_encr_start, "
		"eap_sim_msg_add_encr_end, eap_sim_parse_encr");
	for (i = 0; i < ARRAY_SIZE(encr_inputs); i++) {
		const struct encr_input *in = &encr_inputs[i];
		struct eap_sim_msg *msg;
		struct wpabuf *buf;
		struct eap_sim_attrs attr;
		u8 iv[EAP_SIM_IV_LEN], *plain;
		size_t pad;

		unhex(in->iv, iv, sizeof(iv));
		msg = eap_sim_msg_init(EAP_CODE_REQUEST, 1, EAP_TYPE_AKA,
				       EAP_AKA_SUBTYPE_REAUTHENTICATION);
		set_iv(iv);
		if (eap_sim_msg_add_encr_start(msg, EAP_SIM_AT_IV,
					       EAP_SIM_AT_ENCR_DATA) < 0)
			die("eap_sim_msg_add_encr_start failed");
		switch (in->kind) {
		case ENCR_COUNTER:
			add_counter(msg, 1);
			break;
		case ENCR_COUNTER_NONCE:
			add_counter(msg, 1);
			add_nonce_s(msg, nonce_s);
			break;
		case ENCR_PSEUDONYM:
			add_id_attr(msg, EAP_SIM_AT_NEXT_PSEUDONYM, "2s7ah6n9");
			break;
		case ENCR_COUNTER_NONCE_REAUTH:
			add_counter(msg, 2);
			add_nonce_s(msg, nonce_s);
			/* 17 文字: 4 + 17 = 21 → 24 バイト。合計 4 + 20 + 24 = 48 */
			add_id_attr(msg, EAP_SIM_AT_NEXT_REAUTH_ID,
				    "4reauth01@example");
			break;
		case ENCR_COUNTER_TOO_SMALL:
			add_counter(msg, 3);
			eap_sim_msg_add(msg, EAP_SIM_AT_COUNTER_TOO_SMALL, 0,
					NULL, 0);
			break;
		case ENCR_PSEUDONYM_REAUTH:
			add_id_attr(msg, EAP_SIM_AT_NEXT_PSEUDONYM,
				    "w8w49PexCazWJ&xCIARmxuMKht5S1sxRDqXSEFBEg3"
				    "DcZP9cIxTe5J4OyIwNGVzxeJOU1G");
			add_id_attr(msg, EAP_SIM_AT_NEXT_REAUTH_ID,
				    "Y24fNSrz8BP274jOJaF17WfxI8YO7QX00pMXk9XMMV"
				    "OwlXxqp7AdqoKOq5aRQXB@uma.example.org");
			break;
		}
		if (eap_sim_msg_add_encr_end(msg, k_encr,
					     EAP_SIM_AT_PADDING) < 0)
			die("eap_sim_msg_add_encr_end failed");
		buf = eap_sim_msg_finish(msg, EAP_TYPE_AKA, NULL, NULL, 0);
		if (!buf)
			die("eap_sim_msg_finish failed");

		parse_packet(buf, EAP_TYPE_AKA, &attr);
		if (os_memcmp(attr.iv, iv, sizeof(iv)) != 0)
			die("AT_IV mismatch");
		plain = decrypt_encr(EAP_TYPE_AKA, k_encr, &attr);
		pad = padding_len(plain, attr.encr_data_len);
		if (pad != in->want_pad)
			die("%s: padding length %zu, want %zu", in->name, pad,
			    in->want_pad);
		seen_pad[pad / 4] = 1;

		jw_case_begin(&w, in->name);
		jw_hex(&w, "k_encr", k_encr, sizeof(k_encr));
		jw_hex(&w, "iv", iv, sizeof(iv));
		jw_hex(&w, "attributes", plain, attr.encr_data_len - pad);
		jw_int(&w, "padding_len", (long) pad);
		jw_hex(&w, "plaintext", plain, attr.encr_data_len);
		jw_hex(&w, "ciphertext", attr.encr_data, attr.encr_data_len);
		jw_case_end(&w);

		os_free(plain);
		wpabuf_free(buf);
	}
	jw_close(&w);

	for (i = 0; i < ARRAY_SIZE(seen_pad); i++)
		if (!seen_pad[i])
			die("encr_data: padding length %zu not covered", i * 4);
}

/* -------------------------------------------------------------------------
 * packets.json: AT_IV・AT_ENCR_DATA・AT_MAC を含む完成したパケット
 * （RFC 4187 §9・§10.12・§10.15、RFC 9048）
 * ------------------------------------------------------------------------- */

static const char *pkt_rand = "101112131415161718191a1b1c1d1e1f";
static const char *pkt_autn = "202122232425262728292a2b2c2d2e2f";

enum pkt_kind {
	PKT_REAUTH_REQUEST,
	PKT_REAUTH_RESPONSE,
	PKT_REAUTH_RESPONSE_COUNTER_TOO_SMALL,
	PKT_CHALLENGE_NEXT_IDS,
	PKT_NOTIFICATION_AFTER_REAUTH,
	PKT_NOTIFICATION_RESPONSE,
};

struct pkt_input {
	const char *name;
	int method;
	enum pkt_kind kind;
	const char *iv; /* AT_ENCR_DATA を使わないなら NULL */
};

static const struct pkt_input pkt_inputs[] = {
	{ "aka_reauth_request", EAP_TYPE_AKA, PKT_REAUTH_REQUEST,
	  "11111111111111111111111111111111" },
	{ "aka_reauth_response", EAP_TYPE_AKA, PKT_REAUTH_RESPONSE,
	  "22222222222222222222222222222222" },
	{ "aka_reauth_response_counter_too_small", EAP_TYPE_AKA,
	  PKT_REAUTH_RESPONSE_COUNTER_TOO_SMALL,
	  "33333333333333333333333333333333" },
	{ "aka_challenge_next_ids", EAP_TYPE_AKA, PKT_CHALLENGE_NEXT_IDS,
	  "44444444444444444444444444444444" },
	{ "aka_notification_after_reauth", EAP_TYPE_AKA,
	  PKT_NOTIFICATION_AFTER_REAUTH, "55555555555555555555555555555555" },
	{ "aka_notification_response", EAP_TYPE_AKA,
	  PKT_NOTIFICATION_RESPONSE, NULL },
	{ "aka_prime_reauth_request", EAP_TYPE_AKA_PRIME, PKT_REAUTH_REQUEST,
	  "66666666666666666666666666666666" },
	{ "aka_prime_reauth_response", EAP_TYPE_AKA_PRIME,
	  PKT_REAUTH_RESPONSE, "77777777777777777777777777777777" },
	{ "aka_prime_reauth_response_counter_too_small", EAP_TYPE_AKA_PRIME,
	  PKT_REAUTH_RESPONSE_COUNTER_TOO_SMALL,
	  "88888888888888888888888888888888" },
	{ "aka_prime_challenge_next_ids", EAP_TYPE_AKA_PRIME,
	  PKT_CHALLENGE_NEXT_IDS, "99999999999999999999999999999999" },
	{ "aka_prime_notification_after_reauth", EAP_TYPE_AKA_PRIME,
	  PKT_NOTIFICATION_AFTER_REAUTH, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
	{ "aka_prime_notification_response", EAP_TYPE_AKA_PRIME,
	  PKT_NOTIFICATION_RESPONSE, NULL },
};

static void gen_packets(const char *dir)
{
	struct jw w;
	size_t i;
	u8 nonce_s[EAP_SIM_NONCE_S_LEN];
	u8 rand[EAP_AKA_RAND_LEN], autn[EAP_AKA_AUTN_LEN];

	unhex(nonce_s_hex, nonce_s, sizeof(nonce_s));
	unhex(pkt_rand, rand, sizeof(rand));
	unhex(pkt_autn, autn, sizeof(autn));

	jw_open(&w, dir, "packets.json",
		"hostap " HOSTAP_DESC ": eap_sim_msg_* (AT_IV, AT_ENCR_DATA, "
		"AT_MAC), eap_sim_add_mac, eap_sim_add_mac_sha256, "
		"eap_sim_verify_mac, eap_sim_verify_mac_sha256, "
		"eap_sim_parse_encr");
	for (i = 0; i < ARRAY_SIZE(pkt_inputs); i++) {
		const struct pkt_input *in = &pkt_inputs[i];
		int prime = in->method == EAP_TYPE_AKA_PRIME;
		const u8 *k_encr = prime ? akap1_k_encr : aka1_k_encr;
		const u8 *k_aut = prime ? akap1_k_aut : aka1_k_aut;
		size_t k_aut_len = prime ? EAP_AKA_PRIME_K_AUT_LEN :
			EAP_SIM_K_AUT_LEN;
		const u8 *extra = NULL;
		size_t extra_len = 0;
		struct eap_sim_msg *msg;
		struct wpabuf *buf;
		struct eap_sim_attrs attr;
		u8 iv[EAP_SIM_IV_LEN], *plain = NULL;
		int code, subtype;

		switch (in->kind) {
		case PKT_REAUTH_REQUEST:
			code = EAP_CODE_REQUEST;
			subtype = EAP_AKA_SUBTYPE_REAUTHENTICATION;
			break;
		case PKT_REAUTH_RESPONSE:
		case PKT_REAUTH_RESPONSE_COUNTER_TOO_SMALL:
			code = EAP_CODE_RESPONSE;
			subtype = EAP_AKA_SUBTYPE_REAUTHENTICATION;
			/* RFC 4187 §9.8: MAC は EAP パケット | NONCE_S に対して計算する */
			extra = nonce_s;
			extra_len = sizeof(nonce_s);
			break;
		case PKT_CHALLENGE_NEXT_IDS:
			code = EAP_CODE_REQUEST;
			subtype = EAP_AKA_SUBTYPE_CHALLENGE;
			break;
		case PKT_NOTIFICATION_AFTER_REAUTH:
			code = EAP_CODE_REQUEST;
			subtype = EAP_AKA_SUBTYPE_NOTIFICATION;
			break;
		case PKT_NOTIFICATION_RESPONSE:
		default:
			code = EAP_CODE_RESPONSE;
			subtype = EAP_AKA_SUBTYPE_NOTIFICATION;
			break;
		}

		msg = eap_sim_msg_init(code, 0x40 + (int) i, in->method,
				       subtype);

		/* 暗号化しない属性（AT_ENCR_DATA より前） */
		if (in->kind == PKT_CHALLENGE_NEXT_IDS) {
			eap_sim_msg_add(msg, EAP_SIM_AT_RAND, 0, rand,
					sizeof(rand));
			eap_sim_msg_add(msg, EAP_SIM_AT_AUTN, 0, autn,
					sizeof(autn));
			if (prime) {
				eap_sim_msg_add(msg, EAP_SIM_AT_KDF,
						EAP_AKA_PRIME_KDF, NULL, 0);
				eap_sim_msg_add(msg, EAP_SIM_AT_KDF_INPUT,
						os_strlen(RFC9048_C1_NETNAME),
						(const u8 *) RFC9048_C1_NETNAME,
						os_strlen(RFC9048_C1_NETNAME));
			}
		}
		if (in->kind == PKT_NOTIFICATION_AFTER_REAUTH) {
			/* 0 = General failure after authentication（P=0, S=0） */
			eap_sim_msg_add(msg, EAP_SIM_AT_NOTIFICATION, 0, NULL,
					0);
		}

		/* AT_IV と AT_ENCR_DATA */
		if (in->iv) {
			unhex(in->iv, iv, sizeof(iv));
			set_iv(iv);
			if (eap_sim_msg_add_encr_start(msg, EAP_SIM_AT_IV,
						       EAP_SIM_AT_ENCR_DATA) < 0)
				die("eap_sim_msg_add_encr_start failed");
			switch (in->kind) {
			case PKT_REAUTH_REQUEST:
				add_counter(msg, 1);
				add_nonce_s(msg, nonce_s);
				add_id_attr(msg, EAP_SIM_AT_NEXT_REAUTH_ID,
					    prime ?
					    "8next0002@wlan.mnc001.mcc001.3gppnetwork.org" :
					    "4next0002@wlan.mnc001.mcc001.3gppnetwork.org");
				break;
			case PKT_REAUTH_RESPONSE:
				add_counter(msg, 1);
				break;
			case PKT_REAUTH_RESPONSE_COUNTER_TOO_SMALL:
				add_counter(msg, 1);
				eap_sim_msg_add(msg,
						EAP_SIM_AT_COUNTER_TOO_SMALL,
						0, NULL, 0);
				break;
			case PKT_CHALLENGE_NEXT_IDS:
				add_id_attr(msg, EAP_SIM_AT_NEXT_PSEUDONYM,
					    "2s7ah6n9q3fc8w4x");
				add_id_attr(msg, EAP_SIM_AT_NEXT_REAUTH_ID,
					    prime ?
					    "8next0001@wlan.mnc001.mcc001.3gppnetwork.org" :
					    "4next0001@wlan.mnc001.mcc001.3gppnetwork.org");
				break;
			case PKT_NOTIFICATION_AFTER_REAUTH:
				add_counter(msg, 1);
				break;
			default:
				die("unexpected AT_ENCR_DATA for %s",
				    in->name);
			}
			if (eap_sim_msg_add_encr_end(msg, (u8 *) k_encr,
						     EAP_SIM_AT_PADDING) < 0)
				die("eap_sim_msg_add_encr_end failed");
		}

		eap_sim_msg_add_mac(msg, EAP_SIM_AT_MAC);
		buf = eap_sim_msg_finish(msg, in->method, k_aut, extra,
					 extra_len);
		if (!buf)
			die("eap_sim_msg_finish failed");

		/* hostap 自身で検証してから書き出す */
		parse_packet(buf, in->method, &attr);
		if (!attr.mac)
			die("AT_MAC missing");
		if (verify_mac(in->method, k_aut, buf, attr.mac, extra,
			       extra_len) != 0)
			die("%s: MAC verification failed", in->name);
		if (extra_len > 0 &&
		    verify_mac(in->method, k_aut, buf, attr.mac, NULL, 0) == 0)
			die("%s: MAC verified without extra data", in->name);
		if (in->iv)
			plain = decrypt_encr(in->method, k_encr, &attr);

		jw_case_begin(&w, in->name);
		jw_str(&w, "method", prime ? "aka_prime" : "aka");
		jw_hex(&w, "k_encr", k_encr, EAP_SIM_K_ENCR_LEN);
		jw_hex(&w, "k_aut", k_aut, k_aut_len);
		jw_hex(&w, "iv", in->iv ? iv : NULL, in->iv ? sizeof(iv) : 0);
		jw_hex(&w, "plaintext", plain, plain ? attr.encr_data_len : 0);
		jw_hex(&w, "extra", extra, extra_len);
		jw_hex(&w, "mac", attr.mac, EAP_SIM_MAC_LEN);
		jw_hex(&w, "packet", wpabuf_head_u8(buf), wpabuf_len(buf));
		jw_case_end(&w);

		os_free(plain);
		wpabuf_free(buf);
	}
	jw_close(&w);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <output directory>\n", argv[0]);
		return 2;
	}

	selftest_rfc9048();

	/* 後のファイルが前のファイルの鍵を使うので、この順に生成する */
	gen_aka_keys(argv[1]);
	gen_aka_prime_keys(argv[1]);
	gen_reauth_keys_aka(argv[1]);
	gen_reauth_keys_aka_prime(argv[1]);
	gen_encr_data(argv[1]);
	gen_packets(argv[1]);

	return 0;
}
