#!/bin/sh
# Run the QUIC Interop Runner against the erlang_quic endpoint image.
#
#   interop/run.sh [-s SERVERS] [-c CLIENTS] [-t TESTS] [-i IMAGE] [-o OUTDIR]
#
# SERVERS and CLIENTS are comma-separated runner names (default
# erlang-quic). TESTS is a comma-separated list, or core or extended.
set -eu

RUNNER_REPO=https://github.com/quic-interop/quic-interop-runner.git
RUNNER_REV=d3d74cd27a6ed3e10cc452562cb3fca9b2519281
CORE=handshake,transfer,multiplexing,retry,resumption,zerortt,http3,chacha20,v2,keyupdate
EXTENDED=longrtt,blackhole,ecn,amplificationlimit,handshakeloss,transferloss,handshakecorruption,transfercorruption,ipv6,rebind-port,rebind-addr,connectionmigration

top=$(cd "$(dirname "$0")/.." && pwd)
work=${QIR_WORKDIR:-$top/_build/interop}
servers=erlang-quic
clients=erlang-quic
tests=core
image=erlang-quic-interop
out=

while getopts s:c:t:i:o: opt; do
    case $opt in
        s) servers=$OPTARG ;;
        c) clients=$OPTARG ;;
        t) tests=$OPTARG ;;
        i) image=$OPTARG ;;
        o) out=$OPTARG ;;
        *) sed -n '2,9p' "$0" >&2; exit 2 ;;
    esac
done
case $tests in
    core) tests=$CORE ;;
    extended) tests=$EXTENDED ;;
esac
out=${out:-$work/results/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$work" "$out"
out=$(cd "$out" && pwd)

if [ ! -d "$work/runner" ]; then
    git clone -q "$RUNNER_REPO" "$work/runner"
fi
git -C "$work/runner" fetch -q origin
git -C "$work/runner" checkout -q -f "$RUNNER_REV"

docker build -q -t erlang-quic-qir -f "$top/interop/runner.Dockerfile" "$top/interop" >/dev/null

# The runner's compose file and logs use host paths, so they are mounted
# at the same paths inside its container.
docker run --rm --network host \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /tmp:/tmp -v "$work:$work" -v "$out:$out" \
    -w "$work/runner" erlang-quic-qir sh -c '
        python3 - "$0" <<PY
import json, sys
p = "implementations_quic.json"
d = json.load(open(p))
d["erlang-quic"] = {"image": sys.argv[1], "url": "https://github.com/benoitc/erlang_quic", "role": "both"}
json.dump(d, open(p, "w"), indent=2)
PY
        # The ngtcp2 example server runs out of descriptors at the default 1024.
        sed -i "s/^      memlock: 67108864\$/&\n      nofile: 65536/" docker-compose.yml
        exec python3 run.py -s "$1" -c "$2" -t "$3" -j "$4/result.json" -l "$4/logs"
    ' "$image" "$servers" "$clients" "$tests" "$out"
echo "results in $out"
