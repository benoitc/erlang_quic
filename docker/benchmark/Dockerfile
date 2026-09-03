# Linux benchmark image.
#
#   docker build -f docker/benchmark/Dockerfile -t quic-bench .
#   docker run --rm quic-bench                    # default: sink, 10 MB, 5 runs
#   docker run --rm quic-bench 50 9               # 50 MB, 9 runs
#
# Linux is where the send path has UDP_SEGMENT and GRO, so it is the only
# platform on which a per-packet change can be judged against the numbers
# other implementations publish. cmake and the OpenSSL headers are here so
# an optional NIF can be built in the same image with QUIC_OFFLOAD=1.

ARG OTP_VERSION=28

FROM erlang:${OTP_VERSION}

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/erlang/rebar3/releases/download/3.24.0/rebar3 \
    && chmod +x rebar3 \
    && mv rebar3 /usr/local/bin/

COPY src /build/src
COPY include /build/include
COPY test /build/test
COPY bench /build/bench
COPY rebar.config /build/rebar.config
COPY rebar.lock /build/rebar.lock
COPY certs /build/certs

RUN rebar3 compile && rebar3 as test compile

ENTRYPOINT ["escript", "bench/run_sink_bench.erl"]
