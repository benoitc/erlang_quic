%%% -*- erlang -*-
%%%
%%% Packets the loss timer declares lost reach the congestion controller as
%%% the ones an acknowledgement declares lost do: only in-flight packets
%%% leave its count, and only they make a congestion event (RFC 9002
%%% Appendix B.8). A lost ACK-only packet changes neither.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_loss_timer_cc_tests).

-include_lib("eunit/include/eunit.hrl").

-define(S, quic_connection_test_support).
-define(CWND, 20000).

lost_ack_only_packet_is_not_a_congestion_event_test() ->
    CC = after_timer(false, false, 50),
    ?assertEqual(1000, quic_cc:bytes_in_flight(CC)),
    ?assertEqual(?CWND, quic_cc:cwnd(CC)),
    ?assertNot(quic_cc:in_recovery(CC)).

%% Padded or ack-eliciting, a lost packet leaves the count and cuts the
%% window; the same packet not in flight does neither.
only_in_flight_losses_are_congestion_events_test() ->
    [Padded, AckEliciting, AckOnly] = [
        after_timer(AE, InFlight, 1200)
     || {AE, InFlight} <- [{false, true}, {true, true}, {false, false}]
    ],
    ?assertEqual({1000, 1000, 1000}, {bytes(Padded), bytes(AckEliciting), bytes(AckOnly)}),
    ?assert(quic_cc:cwnd(Padded) < ?CWND),
    ?assert(quic_cc:cwnd(AckEliciting) < ?CWND),
    ?assertEqual(?CWND, quic_cc:cwnd(AckOnly)).

bytes(CC) ->
    quic_cc:bytes_in_flight(CC).

%% Packet 0 of Size bytes, as AckEliciting and InFlight say, goes out a
%% second ago with packet 1, which is acknowledged at once; packet 2, of
%% 1000 bytes, is still out when the loss timer fires.
after_timer(AckEliciting, InFlight, Size) ->
    T = erlang:monotonic_time(millisecond),
    Frames =
        case AckEliciting of
            true -> [ping];
            false -> [{ack, [{0, 0}], 0, undefined}]
        end,
    L0 = quic_loss:on_handshake_confirmed(quic_loss:new()),
    L1 = quic_loss:on_packet_sent(app, L0, 0, Size, AckEliciting, InFlight, Frames, T - 1000),
    L2 = quic_loss:on_packet_sent(app, L1, 1, 1000, true, [ping], T - 1000),
    {L3, [_], [], _} = quic_loss:on_ack_received(app, L2, {ack, 1, 0, 0, []}, T - 990),
    L4 = quic_loss:on_packet_sent(app, L3, 2, 1000, true, [ping], T),
    CC0 = quic_cc:new(#{algorithm => newreno, initial_window => ?CWND}),
    Charged =
        case InFlight of
            true -> Size + 1000;
            false -> 1000
        end,
    S0 = ?S:state_for_admission(0, 0, 1000000, 1000000),
    S1 = ?S:state_set(
        ?S:state_set(S0, loss_state, L4), cc_state, quic_cc:on_packet_sent(CC0, Charged)
    ),
    S2 = quic_connection:handle_loss_timeout(?S:state_set(S1, pto_space, app)),
    ?assertEqual([2], maps:keys(quic_loss:sent_packets(app, ?S:loss_state(S2)))),
    ?S:state_get(S2, cc_state).
