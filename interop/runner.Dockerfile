# The QUIC Interop Runner itself, with what it needs on the host: the
# docker CLI with compose, tshark, and a Python pyshark still runs on.
FROM docker:29-cli AS docker

FROM python:3.12-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
# pyshark is pinned: 0.6's FileCapture teardown crashes against tshark 4.4
# (TSharkCrashException at capture close, retcode 255) and takes the run
# down with it; 0.4.3 and older import distutils, which Python 3.12 removed.
# 0.5.3 is the newest line that both imports on 3.12 and closes captures
# cleanly; verified against a runner pcap before pinning.
RUN pip install --no-cache-dir pycryptodome random-slugs termcolor prettytable pyshark==0.5.3
