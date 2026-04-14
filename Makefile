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

##
## Test convenience targets layered on top of rebar3.
##
## `make test-local` runs everything that doesn't need Docker.
## `make test-docker` spins the docker-compose echo + H3 servers up,
## points the external-server CT suites at them, and tears them down.
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
	rebar3 ct --suite=quic_datagram_e2e_SUITE,\
	quic_lb_e2e_SUITE,\
	quic_client_compliance_SUITE,\
	quic_interop_SUITE,\
	quic_h3_server_SUITE

## Docker stage also covers h3spec_conformance which drives the
## kazu-yamamoto/h3spec container against our in-process H3 server.
test-docker:
	cd docker && docker compose up -d quic-server h3-server
	QUIC_SERVER_HOST=127.0.0.1 H3_SERVER_HOST=127.0.0.1 \
		rebar3 ct --suite=quic_e2e_SUITE,\
		quic_e2e_bbr_SUITE,\
		quic_e2e_cubic_SUITE,\
		quic_h3_e2e_SUITE,\
		quic_h3_h3spec_SUITE \
		|| (cd docker && docker compose down && exit 1)
	cd docker && docker compose down

test-all: test-local test-docker test-static
