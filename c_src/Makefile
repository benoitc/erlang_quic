# Shim so erlang.mk, which runs c_src/Makefile unconditionally when it
# exists, builds the NIF the same way rebar3 does. The real build is
# CMakeLists.txt in this directory.
#
# POSIX make only (no GNU extensions): FreeBSD and NetBSD run this with
# bmake. Opt-in like the rebar3 hook: nothing is built unless
# QUIC_BUILD_NIF=1, and a requested build that fails fails the compile.

BUILD = build

all:
	@if [ "$$QUIC_BUILD_NIF" = 1 ]; then \
	  cmake -S . -B $(BUILD) && cmake --build $(BUILD) \
	  || { echo "quic_crypto_nif: QUIC_BUILD_NIF=1 but the build failed; install cmake, a C compiler and OpenSSL headers, or unset QUIC_BUILD_NIF" >&2; exit 1; }; \
	fi

clean:
	@rm -rf $(BUILD) ../priv/quic_crypto_nif.so

.PHONY: all clean
