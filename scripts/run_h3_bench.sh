#!/bin/bash
set -e

cd "$(dirname "$0")/.."

echo "Compiling..."
rebar3 compile

echo "Compiling benchmark module..."
erlc -pa _build/default/lib/quic/ebin -I include -I _build/default/lib/quic/include -o _build/default/lib/quic/ebin test/quic_h3_bench.erl

echo "Running HTTP/3 benchmarks..."
erl -pa _build/default/lib/*/ebin \
    -noshell \
    -eval "
        application:ensure_all_started(crypto),
        application:ensure_all_started(ssl),
        application:ensure_all_started(quic),
        quic_h3_bench:run(),
        init:stop().
    "
