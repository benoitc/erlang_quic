%%% -*- erlang -*-
%%%
%%% Datagrams that arrive together get the same treatment as a lone one:
%%% a 1-RTT packet for an unknown connection can draw a stateless reset
%%% (RFC 9000 Section 10.3), and an Initial with a version we do not
%%% speak a Version Negotiation packet (Section 6.1), instead of being
%%% dropped or starting a connection.

-module(quic_listener_batch_unrouted_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DCID_LEN, 8).

unknown_short_header_test() ->
    Short = <<16#40, "unknown!", (crypto:strong_rand_bytes(40))/binary>>,
    ?assertEqual(#{unrouted => [Short, Short]}, group([Short, Short])).

unsupported_version_test() ->
    Initial = <<16#C0, 16#1A2A3A4A:32, 8, "client-d", 8, "client-s", 0, 4, 0:32>>,
    ?assertEqual(#{unrouted => [Initial, Initial]}, group([Initial, Initial])).

group(Packets) ->
    Conns = ets:new(conns, [set]),
    try
        quic_listener:group_packets_by_conn(Packets, ?DCID_LEN, Conns, #{})
    after
        ets:delete(Conns)
    end.
