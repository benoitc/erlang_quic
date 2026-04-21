# h3spec runner image
#
# Packages the prebuilt h3spec-linux-x86_64 binary from
# https://github.com/kazu-yamamoto/h3spec/releases into a minimal
# Debian image so the HTTP/3 conformance CT suite can run without
# depending on an external registry.
#
# Build locally:
#   docker build -t erlang_quic/h3spec:local docker/h3spec
#
FROM --platform=linux/amd64 debian:bookworm-slim

ARG H3SPEC_VERSION=v0.1.13

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libgmp10 \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL \
        "https://github.com/kazu-yamamoto/h3spec/releases/download/${H3SPEC_VERSION}/h3spec-linux-x86_64" \
        -o /usr/local/bin/h3spec \
 && chmod +x /usr/local/bin/h3spec

ENTRYPOINT ["/usr/local/bin/h3spec"]
