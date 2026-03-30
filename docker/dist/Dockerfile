# Multi-stage build for QUIC distribution test nodes
#
# Build context should be the root of the erlang_quic project:
#   docker build -f docker/dist/Dockerfile -t quic-dist-test .
#
# Supports Erlang/OTP 26, 27, or 28. Use build arg to select:
#   docker build --build-arg OTP_VERSION=28 ...
#
ARG OTP_VERSION=28

# Stage 1: Build the release
FROM erlang:${OTP_VERSION} AS builder

WORKDIR /build

# Install rebar3
RUN wget https://github.com/erlang/rebar3/releases/download/3.24.0/rebar3 && \
    chmod +x rebar3 && \
    mv rebar3 /usr/local/bin/

# Copy the quic project source (without the test profile plugins)
COPY src /build/quic/src
COPY include /build/quic/include
COPY rebar.lock /build/quic/rebar.lock

# Copy test app sources as an umbrella app
COPY docker/dist/src /build/quic/apps/quic_dist_test/src
COPY docker/dist/config /build/quic/config

# Use the release-specific rebar.config
COPY docker/dist/rebar.config.release /build/quic/rebar.config

# Create rebar.config for the test app
RUN echo '{erl_opts, [debug_info]}.' > /build/quic/apps/quic_dist_test/rebar.config

WORKDIR /build/quic

# Compile everything
RUN rebar3 compile

# Build the release
RUN rebar3 release

# Stage 2: Runtime image
ARG OTP_VERSION=28
FROM erlang:${OTP_VERSION}-slim

# Install required tools
RUN apt-get update && apt-get install -y \
    openssl \
    netcat-openbsd \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the release from builder
COPY --from=builder /build/quic/_build/default/rel/quic_dist_test /app

# Copy startup script
COPY docker/dist/start_node.sh /app/start_node.sh
RUN chmod +x /app/start_node.sh

# Create directories
RUN mkdir -p /app/certs /app/logs

# Environment defaults
ENV NODE_NAME=node1@localhost \
    ERLANG_COOKIE=quic_dist_test_cookie \
    QUIC_CERT_FILE=/app/certs/cert.pem \
    QUIC_KEY_FILE=/app/certs/key.pem \
    QUIC_DIST_PORT=9100 \
    EXPECTED_NODES=2 \
    SEED_NODE="" \
    CLUSTER_NODES="" \
    CLUSTER_NODES_CONFIG="[]"

# Expose QUIC port (UDP)
EXPOSE 9100/udp

# Health check - verify the beam process is running
# Note: can't use ping as it requires epmd, which is disabled for QUIC distribution
HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=3 \
    CMD pgrep -x beam.smp > /dev/null || exit 1

ENTRYPOINT ["/app/start_node.sh"]
