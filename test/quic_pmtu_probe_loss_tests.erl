%%% -*- erlang -*-
%%%
%%% A PMTU probe is ack-eliciting and in flight (RFC 9000 Section 14.4,
%%% RFC 9002 Section 2): it counts in bytes_in_flight and waits for the
%%% congestion window like any other packet. Losing one is the expected
%%% outcome of probing past the path MTU, so it leaves the flight without
%%% a congestion response (RFC 9000 Section 14.4, RFC 8899 Section 3).
%%%
%%% A lost probe must not let a disconnect timeout declare a healthy idle
%%% peer dead; quic_pmtu_raise_probe_SUITE covers that end to end.

-module(quic_pmtu_probe_loss_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(CWND, 20000).

probe_is_in_flight_test() ->
    S = quic_connection:send_pmtu_probe(prober(?CWND)),
    [#sent_packet{ack_eliciting = AE, frames = Frames, size = Size}] = sent(S),
    ?assert(AE),
    ?assert(lists:member(padding, Frames)),
    ?assert(Size > 1200),
    ?assertEqual(Size, quic_loss:bytes_in_flight(S#state.loss_state)),
    ?assertEqual(Size, quic_cc:bytes_in_flight(S#state.cc_state)),
    ?assertNotEqual(undefined, (S#state.pmtu_state)#pmtu_state.probe_pn).

%% Refused by the window, the probe is not sent and not recorded; the
%% probe timer tries again.
probe_waits_for_the_window_test() ->
    S0 = prober(100),
    S = quic_connection:send_pmtu_probe(S0),
    ?assertEqual([], sent(S)),
    ?assertEqual(undefined, (S#state.pmtu_state)#pmtu_state.probe_pn),
    ?assertNotEqual(undefined, S#state.pmtu_probe_timer).

%% Declared lost by an ACK of later packets: out of flight, window intact.
probe_lost_on_ack_is_not_congestion_test() ->
    S0 = quic_connection:send_pmtu_probe(prober(?CWND)),
    S1 = lists:foldl(fun(_, Acc) -> quic_connection:send_frame(ping, Acc) end, S0, [1, 2, 3]),
    Cwnd = quic_cc:cwnd(S1#state.cc_state),
    S2 = quic_connection:process_frame(app, {ack, [{3, 2}], 0, undefined}, S1),
    %% The next probe may follow; the lost one is gone.
    Left = sent(S2),
    ?assertNot(lists:keymember(0, #sent_packet.pn, Left)),
    %% Slow start grows it with the acknowledged PINGs; nothing cuts it.
    ?assert(quic_cc:cwnd(S2#state.cc_state) >= Cwnd),
    ?assertNot(quic_cc:in_recovery(S2#state.cc_state)),
    ?assertEqual(
        lists:sum([Sz || #sent_packet{size = Sz} <- Left]),
        quic_cc:bytes_in_flight(S2#state.cc_state)
    ).

%% Declared lost by the loss timer: the same.
probe_lost_on_timeout_is_not_congestion_test() ->
    S0 = quic_connection:send_pmtu_probe(prober(?CWND)),
    [Probe] = sent(S0),
    Cwnd = quic_cc:cwnd(S0#state.cc_state),
    S1 = quic_connection:apply_lost_packets(app, [Probe], S0),
    ?assertEqual(Cwnd, quic_cc:cwnd(S1#state.cc_state)),
    ?assertNot(quic_cc:in_recovery(S1#state.cc_state)),
    ?assertEqual(0, quic_cc:bytes_in_flight(S1#state.cc_state)).

%% Fence: lost data still cuts the window.
lost_data_is_congestion_test() ->
    S0 = quic_connection:send_frame({max_data, 1000000}, prober(?CWND)),
    [Data] = sent(S0),
    Cwnd = quic_cc:cwnd(S0#state.cc_state),
    S1 = quic_connection:apply_lost_packets(app, [Data], S0),
    ?assert(quic_cc:cwnd(S1#state.cc_state) < Cwnd).

%% A connected client ready to probe, with Room bytes of congestion window.
prober(Room) ->
    S = quic_connection_test_support:state_for_admission(0, 0, 1000000, 1000000),
    CC = quic_cc:new(#{algorithm => newreno, initial_window => ?CWND}),
    S#state{
        loss_state = quic_loss:on_handshake_confirmed(quic_loss:new()),
        cc_state = quic_cc:on_packet_sent(CC, ?CWND - Room),
        owner = self(),
        transport_params = #{},
        max_data_local = 1000000,
        pmtu_state = quic_pmtu:on_connection_established(1500, quic_pmtu:new())
    }.

sent(State) ->
    [P || {_, P} <- lists:sort(maps:to_list(quic_loss:sent_packets(app, State#state.loss_state)))].
