%%% -*- erlang -*-
%%%
%%% The congestion window a controller was configured with.
%%%
%%% cwnd evolves from the moment the connection sends, so once it has
%%% moved there is no way to recover the configured starting value from
%%% the controller unless it was kept. A reset that rebuilds the
%%% controller instead would silently discard the algorithm, MTU and
%%% window options the connection was created with.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cc_initial_window_tests).

-include_lib("eunit/include/eunit.hrl").

%% A fresh controller starts at the window it retains, for every
%% algorithm.
fresh_cwnd_is_the_initial_window_test() ->
    [
        ?assertEqual(
            quic_cc:cwnd(quic_cc:new(#{algorithm => Alg})),
            quic_cc:initial_window(quic_cc:new(#{algorithm => Alg})),
            atom_to_list(Alg)
        )
     || Alg <- [newreno, cubic, bbr]
    ].

%% A configured window is what is retained, not the default: a test
%% using the default could not tell the two apart.
configured_window_is_retained_test() ->
    [
        ?assertEqual(
            65536,
            quic_cc:initial_window(
                quic_cc:new(#{algorithm => Alg, initial_window => 65536})
            ),
            atom_to_list(Alg)
        )
     || Alg <- [newreno, cubic]
    ].

%% The retained value survives cwnd moving away from it, which is the
%% whole point: it is read after the connection has been running.
retained_window_survives_cwnd_growth_test() ->
    S0 = quic_cc:new(#{algorithm => newreno, initial_window => 65536}),
    S1 = quic_cc:on_packet_sent(S0, 1200),
    S2 = quic_cc:on_packets_acked(S1, 1200),
    ?assertNotEqual(quic_cc:cwnd(S2), 0),
    ?assertEqual(65536, quic_cc:initial_window(S2)).
