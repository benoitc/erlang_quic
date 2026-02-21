# See LICENSE for licensing information.

PROJECT = quic
PROJECT_DESCRIPTION = Pure Erlang QUIC implementation (RFC 9000).
PROJECT_VERSION = 0.10.2

# Options.

ERLC_OPTS = +debug_info

# Dependencies.

LOCAL_DEPS = crypto ssl public_key

# Standard targets.

ifndef ERLANG_MK_FILENAME
ERLANG_MK_VERSION = 2024.07.02

erlang.mk:
	curl -o $@ https://raw.githubusercontent.com/ninenines/erlang.mk/v$(ERLANG_MK_VERSION)/erlang.mk
endif

include $(if $(ERLANG_MK_FILENAME),$(ERLANG_MK_FILENAME),erlang.mk)
