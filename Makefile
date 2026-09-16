# See LICENSE for licensing information.

PROJECT = quic
PROJECT_DESCRIPTION = Pure Erlang QUIC implementation (RFC 9000).
PROJECT_VERSION = 1.9.1

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

##
## Test convenience targets layered on top of rebar3.
##
## `make test-local` runs everything that doesn't need Docker.
## `make test-docker` starts the peer servers in docker/docker-compose.yml
## and runs the suites that talk to them.
## `make test-all` runs both stages followed by static checks.
##

.PHONY: test-local test-docker test-all test-static

test-static:
	rebar3 fmt --check
	rebar3 xref
	rebar3 lint
	rebar3 dialyzer

test-local:
	rebar3 eunit
	rebar3 proper
	rebar3 ct --suite=quic_e2e_SUITE,\
	quic_e2e_bbr_SUITE,\
	quic_e2e_cubic_SUITE,\
	quic_h3_e2e_SUITE,\
	quic_datagram_e2e_SUITE,\
	quic_lb_e2e_SUITE,\
	quic_cid_rotation_SUITE

test-docker:
	docker compose -f docker/docker-compose.yml up -d --wait
	rebar3 ct --suite=quic_interop_SUITE,\
	quic_client_compliance_SUITE,\
	quic_stream_reassembly_SUITE,\
	quic_h3_server_SUITE
	QUIC_AIOQUIC_HOST=127.0.0.1 QUIC_AIOQUIC_PORT=4435 \
	QUIC_QUICGO_HOST=127.0.0.1 QUIC_QUICGO_PORT=4434 \
	rebar3 ct --suite=quic_h3_0rtt_SUITE

test-all: test-local test-docker test-static
