# See LICENSE for licensing information.

PROJECT = quic
PROJECT_DESCRIPTION = Pure Erlang QUIC implementation (RFC 9000).
PROJECT_VERSION = 0.10.1

# Dependencies.

LOCAL_DEPS = crypto ssl public_key

# Standard targets.

include $(if $(ERLANG_MK_FILENAME),$(ERLANG_MK_FILENAME),erlang.mk)
