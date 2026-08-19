# Builds the optional AEAD-context NIF. Links against the SAME
# libcrypto that OTP's own crypto NIF uses (resolved via ldd), so
# loading this NIF never pins an incompatible OpenSSL into the VM
# before crypto.so loads. Falls back to plain -lcrypto when the
# lookup fails.

ERTS_INCLUDE := $(shell erl -noshell -eval 'io:format("~ts/erts-~ts/include", [code:root_dir(), erlang:system_info(version)]), halt().')
CRYPTO_SO := $(shell erl -noshell -eval 'io:format("~ts", [filename:join([code:lib_dir(crypto), "priv", "lib", "crypto.so"])]), halt().')
OPENSSL_LIB := $(shell ldd "$(CRYPTO_SO)" 2>/dev/null | awk '/libcrypto/ && $$3 != "" {print $$3}')
OPENSSL_LIBDIR := $(dir $(OPENSSL_LIB))

CFLAGS ?= -O2 -Wall -Wextra
LDLIBS := -lcrypto
PRIV := ../priv

ifneq ($(strip $(OPENSSL_LIBDIR)),)
LDFLAGS += -L$(OPENSSL_LIBDIR) -Wl,-rpath,$(OPENSSL_LIBDIR)
CFLAGS += -I$(OPENSSL_LIBDIR)../include
endif

$(PRIV)/quic_crypto_nif.so: quic_crypto_nif.c
	mkdir -p $(PRIV)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -I"$(ERTS_INCLUDE)" $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(PRIV)/quic_crypto_nif.so

.PHONY: clean
