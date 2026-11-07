# The QUIC Interop Runner itself, with what it needs on the host: the
# docker CLI with compose, tshark, and a Python pyshark still runs on.
FROM docker:29-cli AS docker

FROM python:3.12-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
RUN pip install --no-cache-dir pycryptodome random-slugs termcolor prettytable pyshark
