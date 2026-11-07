# Endpoint image for the QUIC Interop Runner: one image for both roles,
# chosen by ROLE, on the runner's network simulator endpoint.
#
#   docker build -t erlang-quic-interop -f interop/Dockerfile .

FROM erlang:28 AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY rebar.config ./
COPY src ./src
COPY include ./include
COPY c_src ./c_src
COPY priv ./priv
ENV QUIC_BUILD_NIF=1
RUN rebar3 compile \
    && rebar3 as interop_server escriptize \
    && rebar3 as interop_client escriptize

# The simulator endpoint ships OTP 25 and OpenSSL 3.0, so the OTP 28
# runtime and its OpenSSL come from the builder.
FROM martenseemann/quic-network-simulator-endpoint:latest
COPY --from=builder /usr/local/lib/erlang /usr/local/lib/erlang
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3 /opt/ossl/
RUN ln -sf /usr/local/lib/erlang/bin/erl /usr/local/bin/erl \
    && ln -sf /usr/local/lib/erlang/bin/escript /usr/local/bin/escript
WORKDIR /app
COPY --from=builder /app/_build/interop_server/bin/quic_interop_server /app/
COPY --from=builder /app/_build/interop_client/bin/quic_interop_client /app/
COPY --from=builder /app/_build/default/lib /app/lib
# _build's priv is a symlink to the source priv, which holds the NIF.
RUN rm -rf /app/lib/quic/priv
COPY --from=builder /app/priv /app/lib/quic/priv
ENV ERL_LIBS=/app/lib
RUN mkdir -p /www /certs /downloads /logs
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
