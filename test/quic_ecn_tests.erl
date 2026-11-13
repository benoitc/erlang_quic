%%% -*- erlang -*-
%%%
%%% ECN in the congestion response, RFC 9002 Section 7.1 and Appendix
%%% B.7: each packet number space keeps the highest ECN-CE count its
%%% peer reported, and an increase is a congestion event for the
%%% largest acknowledged packet.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_ecn_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SIZE, 1200).

%%====================================================================
%% CE counts and the congestion event
%%====================================================================

ce_increase_is_a_congestion_event_test() ->
    S0 = state(newreno, [{initial, 0, -100}]),
    Cwnd = cwnd(S0),
    S1 = ack(initial, 0, {0, 0, 1}, S0),
    ?assert(quic_cc:in_recovery(S1#state.cc_state)),
    ?assert(cwnd(S1) < Cwnd),
    ?assertEqual(1, ce_count(initial, S1)).

%% A count no higher than the space's last one is no event.
ce_without_increase_is_no_event_test() ->
    S0 = set_ce_count(initial, 5, state(newreno, [{initial, 0, -100}])),
    Plain = ack(initial, 0, undefined, S0),
    [
        ?assertEqual(cwnd(Plain), cwnd(ack(initial, 0, {0, 0, CE}, S0)))
     || CE <- [3, 5]
    ],
    ?assertEqual(5, ce_count(initial, ack(initial, 0, {0, 0, 3}, S0))).

%% Each space counts on its own: a CE increase in one space after a
%% higher count in another is still an event.
ce_counts_are_per_space_test() ->
    %% Packet 1 goes out after the recovery the first ACK starts.
    S0 = state(
        newreno,
        [{initial, 0, -100}, {handshake, 0, -100}, {handshake, 1, 1000}],
        #{min_recovery_duration => 0}
    ),
    S1 = ack(initial, 0, {0, 0, 5}, S0),
    ?assert(quic_cc:in_recovery(S1#state.cc_state)),
    WithCe = ack(handshake, 1, {0, 0, 1}, S1),
    Without = ack(handshake, 1, undefined, S1),
    ?assert(cwnd(WithCe) < cwnd(Without)),
    ?assertEqual(5, ce_count(initial, WithCe)),
    ?assertEqual(1, ce_count(handshake, WithCe)).

%% A CE increase for a packet sent before the current recovery started
%% does not cut the window again.
ce_for_packet_sent_before_recovery_does_not_cut_again_test() ->
    S0 = state(newreno, [{initial, 0, -100}, {initial, 1, -100}]),
    S1 = ack(initial, 0, {0, 0, 1}, S0),
    Cwnd = cwnd(S1),
    S2 = ack(initial, 1, {0, 0, 2}, S1),
    ?assertEqual(Cwnd, cwnd(S2)),
    ?assertEqual(2, ce_count(initial, S2)).

%% BBR enters recovery on a CE mark without counting it as loss.
bbr_ce_enters_recovery_without_loss_test() ->
    S1 = ack(initial, 0, {0, 0, 1}, state(bbr, [{initial, 0, -100}])),
    #state{cc_state = CC} = S1,
    ?assert(quic_cc:in_recovery(CC)),
    ?assertEqual(0, maps:get(lost, quic_cc_bbr:info(element(3, CC)))).

%% A CE mark is real congestion: the loss episode it joins is no longer
%% undone when its losses later prove spurious.
ce_keeps_the_window_cut_test() ->
    S0 = state(newreno, [{initial, PN, -100} || PN <- lists:seq(0, 4)]),
    %% ACK of 4 declares 0 and 1 lost.
    S1 = ack(initial, 4, undefined, S0),
    S2 = ack(initial, 2, {0, 0, 1}, S1),
    Cwnd = cwnd(S2),
    Late = quic_connection:process_frame(initial, {ack, [{4, 4}], 0, undefined}, S2),
    ?assertEqual(Cwnd, cwnd(Late)).

%% The same late ACK without the CE mark undoes the cut.
spurious_loss_without_ce_is_undone_test() ->
    S0 = state(newreno, [{initial, PN, -100} || PN <- lists:seq(0, 4)]),
    S1 = ack(initial, 4, undefined, S0),
    S2 = ack(initial, 2, undefined, S1),
    Late = quic_connection:process_frame(initial, {ack, [{4, 4}], 0, undefined}, S2),
    ?assert(cwnd(Late) > cwnd(S2)).

%%====================================================================
%% ECN Integration with ACK Processing
%%====================================================================

%% Test ACK_ECN frame parsing returns ECN counts
ack_ecn_returns_counts_test() ->
    State = quic_ack:new(),

    %% ACK_ECN frame with ECT(0)=100, ECT(1)=50, CE=5
    AckFrame = {ack_ecn, 10, 0, 10, [], 100, 50, 5},
    {_NewState, _AckedPNs, ECN} = quic_ack:process_ack(State, AckFrame),

    ?assertEqual({ecn, 100, 50, 5}, ECN).

%% Test regular ACK frame doesn't return ECN
regular_ack_no_ecn_test() ->
    State = quic_ack:new(),
    AckFrame = {ack, 10, 0, 10, []},

    %% Regular ACK should return just 2-tuple
    Result = quic_ack:process_ack(State, AckFrame),
    ?assertMatch({_, _}, Result),
    ?assertEqual(2, tuple_size(Result)).

%%====================================================================
%% Helpers
%%====================================================================

%% Packets {Space, PN, SentOffsetMs} in flight under Algorithm, and one
%% more packet whose ACK never comes, so recovery does not end on an
%% empty flight.
state(Algorithm, Packets) ->
    state(Algorithm, Packets, #{}).

state(Algorithm, Packets, Opts) ->
    S0 = quic_connection_test_support:state_with_keys(client),
    Now = erlang:monotonic_time(millisecond),
    L = lists:foldl(
        fun({Space, PN, Offset}, Acc) ->
            quic_loss:on_packet_sent(Space, Acc, PN, ?SIZE, true, [ping], Now + Offset)
        end,
        quic_connection_test_support:loss_state(S0),
        Packets
    ),
    CC = lists:foldl(
        fun(_, Acc) -> quic_cc:on_packet_sent(Acc, ?SIZE) end,
        quic_cc:new(Algorithm, Opts),
        [extra | Packets]
    ),
    #state{hs = #hs{pn_initial = PNI, pn_handshake = PNH} = HS} = S0,
    S1 = S0#state{
        hs = HS#hs{pn_initial = PNI#pn_space{next_pn = 8}, pn_handshake = PNH#pn_space{next_pn = 8}}
    },
    quic_connection_test_support:state_set(
        quic_connection_test_support:state_set(S1, loss_state, L), cc_state, CC
    ).

ack(Space, PN, ECN, State) ->
    quic_connection:process_frame(Space, {ack, [{PN, 0}], 0, ECN}, State).

cwnd(#state{cc_state = CC}) -> quic_cc:cwnd(CC).

ce_count(Space, State) ->
    (quic_connection:pn_space(Space, State))#pn_space.ecn_ce_count.

set_ce_count(Space, Count, State) ->
    PN = quic_connection:pn_space(Space, State),
    quic_connection:put_pn_space(Space, PN#pn_space{ecn_ce_count = Count}, State).
