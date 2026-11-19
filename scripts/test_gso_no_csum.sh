#!/bin/sh
#
# Runs test/quic_gso_no_csum_tests.erl over a veth pair whose sending
# end has transmit checksum offload turned off. Run it as root, for the
# network namespaces, after `rebar3 as test compile`. A kernel from 6.11 on segments in software on such
# a device and refuses nothing, so there is nothing to test there.

set -eu

SELF=eq-gso-self
PEER=eq-gso-peer
PEER_ADDR=10.213.7.2

major=$(uname -r | cut -d. -f1)
minor=$(uname -r | cut -d. -f2)
if [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 11 ]; }; then
    echo "Linux $(uname -r) sends GSO without checksum offload; skipped"
    exit 0
fi

cleanup() {
    ip netns del "$SELF" 2>/dev/null || true
    ip netns del "$PEER" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$SELF"
ip netns add "$PEER"
ip -n "$SELF" link add veth0 type veth peer name veth1 netns "$PEER"
ip -n "$SELF" addr add 10.213.7.1/24 dev veth0
ip -n "$PEER" addr add "$PEER_ADDR/24" dev veth1
ip -n "$SELF" link set lo up
ip -n "$SELF" link set veth0 up
ip -n "$PEER" link set veth1 up
ip netns exec "$SELF" ethtool -K veth0 tx off >/dev/null

QUIC_GSO_PEER_NETNS="/run/netns/$PEER" QUIC_GSO_PEER_ADDR="$PEER_ADDR" \
    ip netns exec "$SELF" erl -noshell -pa _build/test/lib/*/ebin _build/test/lib/quic/test \
    -eval 'halt(case eunit:test(quic_gso_no_csum_tests, [verbose]) of ok -> 0; _ -> 1 end).'
