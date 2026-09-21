%%% -*- erlang -*-
%%%
%%% What a Retry does to recovery and congestion state.
%%%
%%% RFC 9002 Section 6.3 resets both, including the timers: the Initial
%%% packets sent before the Retry can never be acknowledged, so leaving
%%% them tracked holds bytes in flight for packets that no longer exist
%%% and arms probes for them.
%%%
%%% Resetting the congestion controller by rebuilding it would be a
%%% different bug: the algorithm, MTU and configured windows are chosen
%%% per connection and have to survive.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_retry_recovery_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% quic_loss:reset_for_retry/2
%%====================================================================

%% Everything in flight comes back, keyed by the space it was sent in.
%% A flat list could not distinguish them: packet numbers restart in
%% each space, so Initial 0 and 0-RTT 0 would be indistinguishable.
discarded_packets_come_back_per_space_test() ->
    S0 = quic_loss:on_packet_sent(initial, quic_loss:new(), 0, 1200, true, [{crypto, 0, <<1>>}], 1),
    S1 = quic_loss:on_packet_sent(app, S0, 0, 300, true, [{stream, 4, 0, <<"hi">>, false}], 2),
    {_Reset, Discarded} = quic_loss:reset_for_retry(S1, 10),
    ?assertMatch([#sent_packet{pn = 0, size = 1200}], maps:get(initial, Discarded)),
    ?assertMatch([#sent_packet{pn = 0, size = 300}], maps:get(app, Discarded)),
    ?assertEqual([], maps:get(handshake, Discarded)).

%% Nothing stays charged: the packets are gone, so the bytes are too.
reset_clears_in_flight_test() ->
    S = quic_loss:on_packet_sent(initial, quic_loss:new(), 0, 1200, true, [ping], 1),
    ?assert(quic_loss:bytes_in_flight(S) > 0),
    {Reset, _} = quic_loss:reset_for_retry(S, 10),
    ?assertEqual(0, quic_loss:bytes_in_flight(Reset)),
    ?assertEqual(0, maps:size(quic_loss:sent_packets(initial, Reset))).

%% The backoff goes with it, or the retried Initial inherits a probe
%% interval earned by packets that were never really lost.
reset_clears_backoff_test() ->
    S = quic_loss:on_pto_expired(quic_loss:on_pto_expired(quic_loss:new())),
    ?assertEqual(2, quic_loss:pto_count(S)),
    {Reset, _} = quic_loss:reset_for_retry(S, 10),
    ?assertEqual(0, quic_loss:pto_count(Reset)).

%% A space with nothing in it is still reported, so callers can read the
%% map without guarding.
reset_reports_every_space_test() ->
    {_Reset, Discarded} = quic_loss:reset_for_retry(quic_loss:new(), 10),
    ?assertEqual([app, handshake, initial], lists:sort(maps:keys(Discarded))).

%%====================================================================
%% quic_cc:reset_for_retry/1
%%====================================================================

%% The window returns to what the connection was configured with, not to
%% a default: asserted from a controller whose cwnd has already moved,
%% or the test could not tell a restore from a no-op.
cc_reset_restores_the_configured_window_test() ->
    [
        begin
            S0 = quic_cc:new(#{algorithm => Alg, initial_window => 65536}),
            S1 = quic_cc:on_packets_acked(quic_cc:on_packet_sent(S0, 1200), 1200),
            ?assertNotEqual(65536, quic_cc:cwnd(S1), atom_to_list(Alg)),
            ?assertEqual(65536, quic_cc:cwnd(quic_cc:reset_for_retry(S1)), atom_to_list(Alg))
        end
     || Alg <- [newreno, cubic]
    ].

%% Configuration survives the reset. Rebuilding the controller instead
%% would silently drop the algorithm and the MTU with it.
cc_reset_keeps_configuration_test() ->
    S0 = quic_cc:new(#{algorithm => cubic, max_datagram_size => 1350}),
    S1 = quic_cc:reset_for_retry(quic_cc:on_packet_sent(S0, 1200)),
    ?assertEqual(cubic, quic_cc:algorithm(S1)),
    ?assertEqual(1350, quic_cc:max_datagram_size(S1)),
    ?assertEqual(0, quic_cc:bytes_in_flight(S1)).
