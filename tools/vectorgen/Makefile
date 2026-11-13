# go-eapaka のテストベクタを外部実装（hostap と Python）から生成する。
# 使い方は README.md を参照。

HOSTAP_TAG    := hostap_2_12
HOSTAP_COMMIT := 831364bf02710ad09c2f27d3efa92abeeb5634c0
HOSTAP_URL    := https://w1.fi/hostap.git

# 先頭が "_" のディレクトリは go のパッケージパターン（./...）の対象外になる
BUILD  := _build
HOSTAP := $(BUILD)/hostap
OUT    := ../../testdata/vectors
PYTHON ?= python3

CC     ?= cc
CFLAGS ?= -O2
CFLAGS += -Wall -Wextra -Wno-unused-parameter -std=gnu99
CPPFLAGS := -I$(HOSTAP)/src -I$(HOSTAP)/src/utils \
	-DEAP_AKA_PRIME \
	-DCONFIG_CRYPTO_INTERNAL \
	-DCONFIG_NO_STDOUT_DEBUG \
	-DCONFIG_NO_WPA_MSG \
	-DHOSTAP_DESC='"$(HOSTAP_TAG) ($(HOSTAP_COMMIT))"'

# hostap の EAP-SIM/AKA 共通ルーチンと、hostap 内蔵の暗号実装。
# OpenSSL は使わない。random.c はリンクせず、random_get_bytes() は
# vectorgen.c が定義する（AT_IV を固定するため）。
HOSTAP_SRCS := \
	src/eap_common/eap_sim_common.c \
	src/utils/common.c \
	src/utils/os_unix.c \
	src/utils/wpabuf.c \
	src/crypto/sha1.c \
	src/crypto/sha1-internal.c \
	src/crypto/sha256.c \
	src/crypto/sha256-internal.c \
	src/crypto/fips_prf_internal.c \
	src/crypto/aes-cbc.c \
	src/crypto/aes-internal.c \
	src/crypto/aes-internal-enc.c \
	src/crypto/aes-internal-dec.c

SRCS := vectorgen.c $(addprefix $(HOSTAP)/,$(HOSTAP_SRCS))
BIN  := $(BUILD)/vectorgen

# MPPE 鍵のベクタ（Python で生成）を hostap の RADIUS 実装で照合するプログラム
MPPECHECK_SRCS := \
	src/utils/common.c \
	src/utils/ip_addr.c \
	src/utils/os_unix.c \
	src/utils/wpabuf.c \
	src/crypto/md5.c \
	src/crypto/md5-internal.c \
	src/crypto/sha1.c \
	src/crypto/sha1-internal.c \
	src/crypto/sha256.c \
	src/crypto/sha256-internal.c
MPPECHECK := $(BUILD)/mppecheck

.PHONY: all fetch build vectors check clean distclean

all: vectors

# hostap を取得し、タグが指すコミットを確認する
fetch: $(HOSTAP)/.verified

$(HOSTAP)/.verified:
	@mkdir -p $(BUILD)
	@if [ ! -d $(HOSTAP)/.git ]; then \
		git -c advice.detachedHead=false clone --depth 1 \
			--branch $(HOSTAP_TAG) $(HOSTAP_URL) $(HOSTAP); \
	fi
	@actual=$$(git -C $(HOSTAP) rev-parse HEAD); \
	if [ "$$actual" != "$(HOSTAP_COMMIT)" ]; then \
		echo "hostap commit mismatch: got $$actual, want $(HOSTAP_COMMIT)" >&2; \
		exit 1; \
	fi
	@touch $@

build: $(BIN) $(MPPECHECK)

$(BIN): $(HOSTAP)/.verified vectorgen.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SRCS)

# radius.c 自体の警告は hostap 側の事情なので抑える
$(MPPECHECK): $(HOSTAP)/.verified mppecheck.c Makefile
	$(CC) $(CFLAGS) -w $(CPPFLAGS) -o $@ mppecheck.c \
		$(addprefix $(HOSTAP)/,$(MPPECHECK_SRCS))

# testdata/vectors/*.json を生成し直す
vectors: $(BIN) $(MPPECHECK)
	@mkdir -p $(OUT)
	./$(BIN) $(OUT)
	$(PYTHON) -I pyvectors.py --mppecheck ./$(MPPECHECK) $(OUT)

# 生成し直した結果が、コミット済みのベクタと一致することを確かめる
check: vectors
	git diff --exit-code -- $(OUT)
	@untracked=$$(git ls-files --others --exclude-standard -- $(OUT)); \
	if [ -n "$$untracked" ]; then \
		echo "untracked vector files: $$untracked" >&2; \
		exit 1; \
	fi

clean:
	rm -f $(BIN) $(MPPECHECK)

distclean:
	rm -rf $(BUILD)
