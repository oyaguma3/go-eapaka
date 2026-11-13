#!/usr/bin/env python3
"""go-eapaka のテストベクタのうち、MPPE 鍵と AT_CHECKCODE を生成する。

go-eapaka とは別に Python の標準ライブラリ（hashlib）だけで実装し、
その結果を JSON に書き出す。外部パッケージは使わない。

使い方: python3 -I pyvectors.py [--mppecheck <mppecheck のパス>] <出力ディレクトリ>

--mppecheck を指定すると、MPPE 鍵の各ケースを hostap の RADIUS 実装
（mppecheck.c）でも照合し、一致しなければ書き出さずに終了する。
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

GENERATOR = "tools/vectorgen/pyvectors.py"

TYPE_AKA = 23
TYPE_AKA_PRIME = 50
CODE_REQUEST = 1
CODE_RESPONSE = 2
SUBTYPE_IDENTITY = 5

AT_PERMANENT_ID_REQ = 10
AT_ANY_ID_REQ = 13
AT_IDENTITY = 14
AT_FULLAUTH_ID_REQ = 17


def write_vectors(out_dir, file_name, source, cases):
    path = os.path.join(out_dir, file_name)
    doc = {"source": source, "generator": GENERATOR, "cases": cases}
    with open(path, "w", encoding="ascii") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"wrote {path} ({len(cases)} cases)")


# ---------------------------------------------------------------------------
# mppe.json: MS-MPPE-Send-Key / MS-MPPE-Recv-Key の暗号化（RFC 2548 §2.4.2-3）
# ---------------------------------------------------------------------------


def mppe_encrypt(key, secret, req_auth, salt):
    """RFC 2548 §2.4.2 の手順で鍵を暗号化し、(平文 P, Salt || C) を返す。"""
    if len(req_auth) != 16 or len(salt) != 2 or not salt[0] & 0x80:
        raise ValueError("invalid Request Authenticator or Salt")
    if not 0 < len(key) <= 255:
        raise ValueError("invalid key length")

    # P = Key-Length（1 バイト）| 鍵 | 0 埋め（16 の倍数にそろえる）
    plain = bytes([len(key)]) + key
    plain += b"\x00" * (-len(plain) % 16)

    # b(1) = MD5(S + R + A)、c(1) = p(1) xor b(1)
    # b(i) = MD5(S + c(i-1))、c(i) = p(i) xor b(i)
    out = bytearray(salt)
    prev = req_auth + salt
    for i in range(0, len(plain), 16):
        b = hashlib.md5(secret + prev).digest()
        c = bytes(p ^ k for p, k in zip(plain[i : i + 16], b))
        out += c
        prev = c
    return plain, bytes(out)


def pattern(n, start=0, step=1):
    return bytes((start + i * step) & 0xFF for i in range(n))


def hostap_mppecheck(mppecheck, case):
    """mppecheck（hostap の encrypt_ms_key / decrypt_ms_key）で照合する。"""
    args = [mppecheck] + [case[k] for k in
                          ("secret", "req_auth", "salt", "key", "encrypted")]
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"{case['name']}: hostap mppecheck failed: "
                 f"{result.stderr.strip()}")


def gen_mppe(out_dir, mppecheck):
    req_auth = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    secret = b"testing123"
    # MD5 のブロック長（64 バイト）を超える共有シークレット
    long_secret = b"s3cr3t-" * 12

    inputs = [
        # (名前, 鍵, 共有シークレット, Request Authenticator, Salt)
        ("mppe_key32", pattern(32, 0x00), secret, req_auth, b"\x80\x01"),
        ("mppe_key32_recv", pattern(32, 0x20), secret, req_auth, b"\x80\x02"),
        ("mppe_key16", pattern(16, 0xA0), secret, req_auth, b"\x81\x23"),
        # 1 + 15 = 16 バイトでパディングなし
        ("mppe_key15_nopad", pattern(15, 0x10), secret, req_auth, b"\xff\xff"),
        ("mppe_key1", b"\x5a", secret, req_auth, b"\x80\x00"),
        # 1 + 47 = 48 バイトでパディングなし（3 ブロック）
        ("mppe_key47_nopad", pattern(47, 0x01, 3), secret, req_auth, b"\x9a\xbc"),
        # 最大長: 1 + 255 = 256 バイト（16 ブロック）
        ("mppe_key255_max", pattern(255, 0xFF, 7), secret, req_auth, b"\xc0\x00"),
        ("mppe_key32_long_secret", pattern(32, 0x40), long_secret,
         pattern(16, 0xF0, 1), b"\x87\x65"),
    ]

    cases = []
    for name, key, sec, ra, salt in inputs:
        plain, enc = mppe_encrypt(key, sec, ra, salt)
        cases.append({
            "name": name,
            "secret": sec.hex(),
            "req_auth": ra.hex(),
            "salt": salt.hex(),
            "key": key.hex(),
            "plaintext": plain.hex(),
            "encrypted": enc.hex(),
        })
        if mppecheck:
            hostap_mppecheck(mppecheck, cases[-1])
    source = ("Python hashlib.md5: independent implementation of RFC 2548 "
              "Section 2.4.2")
    if mppecheck:
        source += " (cross-checked with hostap radius.c encrypt_ms_key and " \
                  "decrypt_ms_key)"
    write_vectors(out_dir, "mppe.json", source, cases)


# ---------------------------------------------------------------------------
# checkcode.json: AT_CHECKCODE（RFC 4187 §10.13、RFC 9048 §3.4.3）
#
# ハッシュの対象は、その認証で送受信した EAP-Request/AKA-Identity と
# EAP-Response/AKA-Identity の EAP パケット全体（EAP ヘッダを含む）を、
# 送受信した順に区切りなしでつないだもの。hostap の eap_aka.c（id_msgs）
# と同じ扱い。AKA-Identity をやり取りしていなければ値は空（長さ 0）。
# ---------------------------------------------------------------------------


def aka_packet(code, ident, method, subtype, attrs):
    body = bytes([method, subtype, 0, 0]) + b"".join(attrs)
    return struct.pack("!BBH", code, ident, 4 + len(body)) + body


def attr_id_req(attr_type):
    # AT_*_ID_REQ: Type | Length=1 | Reserved（2 バイト）
    return bytes([attr_type, 1, 0, 0])


def attr_identity(identity):
    # AT_IDENTITY: Type | Length | Actual Identity Length | Identity | 0 埋め
    value = struct.pack("!H", len(identity)) + identity
    value += b"\x00" * (-(2 + len(value)) % 4)
    return bytes([AT_IDENTITY, (2 + len(value)) // 4]) + value


def identity_exchange(method, rounds):
    """rounds は (Identifier, ID 要求の属性タイプ, 応答する ID) の並び。"""
    packets = []
    for ident, id_req, identity in rounds:
        packets.append(aka_packet(CODE_REQUEST, ident, method,
                                  SUBTYPE_IDENTITY, [attr_id_req(id_req)]))
        packets.append(aka_packet(CODE_RESPONSE, ident, method,
                                  SUBTYPE_IDENTITY, [attr_identity(identity)]))
    return packets


def checkcode(method, packets):
    if not packets:
        return b""
    h = hashlib.sha256 if method == TYPE_AKA_PRIME else hashlib.sha1
    return h(b"".join(packets)).digest()


def gen_checkcode(out_dir):
    realm = b"@wlan.mnc001.mcc001.3gppnetwork.org"
    inputs = []
    for method, prefix, perm in (
        (TYPE_AKA, "aka", b"0"),
        (TYPE_AKA_PRIME, "aka_prime", b"6"),
    ):
        permanent = perm + b"555444333222111" + realm
        inputs += [
            (f"{prefix}_no_identity_exchange", method, []),
            # 仮名で応答する（長さが 4 の倍数でなく、AT_IDENTITY に 0 埋めが入る）
            (f"{prefix}_any_id_pseudonym", method,
             [(1, AT_ANY_ID_REQ, b"2s7ah6n9q3f" + realm)]),
            (f"{prefix}_fullauth_id_permanent", method,
             [(7, AT_FULLAUTH_ID_REQ, permanent)]),
            # AT_ANY_ID_REQ → AT_FULLAUTH_ID_REQ → AT_PERMANENT_ID_REQ
            (f"{prefix}_three_rounds", method,
             [(1, AT_ANY_ID_REQ, (b"4" if method == TYPE_AKA else b"8")
               + b"reauth01" + realm),
              (2, AT_FULLAUTH_ID_REQ, b"2s7ah6n9q3fc" + realm),
              (3, AT_PERMANENT_ID_REQ, permanent)]),
        ]

    cases = []
    for name, method, rounds in inputs:
        packets = identity_exchange(method, rounds)
        cases.append({
            "name": name,
            "method": "aka_prime" if method == TYPE_AKA_PRIME else "aka",
            "packets": [p.hex() for p in packets],
            "checkcode": checkcode(method, packets).hex(),
        })
    write_vectors(
        out_dir, "checkcode.json",
        "Python hashlib.sha1/sha256: independent implementation of RFC 4187 "
        "Section 10.13 and RFC 9048 Section 3.4.3 (hashed data as in hostap "
        "eap_aka.c id_msgs)", cases)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mppecheck",
                        help="path to mppecheck (hostap radius.c cross-check)")
    parser.add_argument("out_dir")
    args = parser.parse_args()
    gen_mppe(args.out_dir, args.mppecheck)
    gen_checkcode(args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
