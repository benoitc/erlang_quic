# Shim so erlang.mk, which runs c_src/Makefile unconditionally when it
# exists, builds the NIF the same way rebar3 does. The real build is
# CMakeLists.txt in this directory.
#
# POSIX make only (no GNU extensions): FreeBSD and NetBSD run this with
# bmake. Best effort, like every other entry point to this build: the
# NIF is an accelerator with a pure-Erlang fallback, so a missing CMake
# or toolchain prints a note and succeeds.

BUILD = build

all:
	@cmake -S . -B $(BUILD) >/dev/null 2>&1 && cmake --build $(BUILD) >/dev/null 2>&1 \
	  && echo "quic_crypto_nif: built ../priv/quic_crypto_nif.so" \
	  || echo "quic_crypto_nif: build skipped (no cmake, toolchain or OpenSSL headers?); using the pure-Erlang crypto path"

clean:
	@rm -rf $(BUILD) ../priv/quic_crypto_nif.so

.PHONY: all clean
