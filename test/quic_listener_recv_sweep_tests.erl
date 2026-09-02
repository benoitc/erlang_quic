%% The listener drains the datagram messages already queued in its
%% mailbox into one receive sweep and dispatches them per source
%% address, so a connection wakes once per sweep instead of once per
%% datagram. Per-flow order must survive the grouping.
-module(quic_listener_recv_sweep_tests).

-include_lib("eunit/include/eunit.hrl").

-define(A, {{10, 0, 0, 1}, 1111}).
-define(B, {{10, 0, 0, 2}, 2222}).

flush() ->
    receive
        _ -> flush()
    after 0 -> ok
    end.

drains_gen_udp_messages_in_order_test() ->
    flush(),
    Sock = sock,
    self() ! {udp, Sock, element(1, ?A), element(2, ?A), <<"a2">>},
    self() ! {udp, Sock, element(1, ?B), element(2, ?B), <<"b1">>},
    self() ! {udp_passive, Sock},
    self() ! {udp, Sock, element(1, ?A), element(2, ?A), <<"a3">>},
    Items = quic_listener:drain_recv_sweep(Sock, gen_udp, 255, [{?A, [<<"a1">>]}]),
    ?assertEqual([{?A, [<<"a1">>]}, {?A, [<<"a2">>]}, {?B, [<<"b1">>]}, {?A, [<<"a3">>]}], Items),
    %% Non-datagram messages stay where they are.
    receive
        {udp_passive, Sock} -> ok
    after 0 -> ?assert(false)
    end.

drains_gro_trains_within_budget_test() ->
    flush(),
    self() ! {gro_packets, element(1, ?B), element(2, ?B), [<<"b1">>, <<"b2">>, <<"b3">>]},
    self() ! {gro_packets, element(1, ?A), element(2, ?A), [<<"a4">>]},
    %% Budget 3 admits the first train (which overshoots) and stops.
    Items = quic_listener:drain_recv_sweep(undefined, socket, 3, [{?A, [<<"a1">>]}]),
    ?assertEqual([{?A, [<<"a1">>]}, {?B, [<<"b1">>, <<"b2">>, <<"b3">>]}], Items),
    receive
        {gro_packets, _, _, [<<"a4">>]} -> ok
    after 0 -> ?assert(false)
    end.

backend_mismatch_is_left_alone_test() ->
    flush(),
    self() ! {gro_packets, element(1, ?A), element(2, ?A), [<<"x">>]},
    ?assertEqual([], quic_listener:drain_recv_sweep(sock, gen_udp, 10, [])),
    receive
        {gro_packets, _, _, _} -> ok
    after 0 -> ?assert(false)
    end.

grouping_keeps_per_flow_order_test() ->
    Items = [
        {?A, [<<"a1">>]}, {?B, [<<"b1">>, <<"b2">>]}, {?A, [<<"a2">>, <<"a3">>]}, {?B, [<<"b3">>]}
    ],
    ?assertEqual(
        #{?A => [<<"a1">>, <<"a2">>, <<"a3">>], ?B => [<<"b1">>, <<"b2">>, <<"b3">>]},
        quic_listener:group_recv_sweep(Items)
    ).
