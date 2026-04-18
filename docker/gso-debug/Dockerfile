FROM erlang:28

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tcpdump \
        strace \
        iproute2 \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/erlang/rebar3/releases/download/3.24.0/rebar3 \
    && chmod +x rebar3 \
    && mv rebar3 /usr/local/bin/

WORKDIR /app
