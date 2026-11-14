%%% -*- erlang -*-
%%%
%%% A packet is in flight when it is ack-eliciting or carries PADDING, until
%%% it is acknowledged, declared lost or discarded with its keys (RFC 9002
%%% Section 2). The loss tracker and the congestion controller each count
%%% the bytes in flight, and both counts follow that rule.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_in_flight_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

-define(S, quic_connection_test_support).

%%====================================================================
%% Loss tracker
%%====================================================================

ack_eliciting_packet_is_in_flight_test() ->
    L = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 1000, true, true, [ping], 0),
    ?assertMatch(#sent_packet{ack_eliciting = true, in_flight = true}, sent(app, 0, L)),
    ?assertEqual(1000, quic_loss:bytes_in_flight(L)).

padded_packet_is_in_flight_test() ->
    L = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 1200, false, true, [ack()], 0),
    ?assertMatch(#sent_packet{ack_eliciting = false, in_flight = true}, sent(app, 0, L)),
    ?assertEqual(1200, quic_loss:bytes_in_flight(L)).

ack_only_packet_is_not_in_flight_test() ->
    L = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 50, false, [ack()], 0),
    ?assertMatch(#sent_packet{ack_eliciting = false, in_flight = false}, sent(app, 0, L)),
    ?assertEqual(0, quic_loss:bytes_in_flight(L)).

ack_removes_only_in_flight_bytes_test() ->
    L0 = mixed(app, quic_loss:new(), 0),
    {L, Acked, [], Meta} = quic_loss:on_ack_received(app, L0, {ack, 2, 0, 2, []}, 10),
    ?assertEqual([0, 1, 2], lists:sort([PN || #sent_packet{pn = PN} <- Acked])),
    ?assertEqual(2200, maps:get(acked_bytes, Meta)),
    ?assertEqual(0, quic_loss:bytes_in_flight(L)).

%% Only the padded packet is acknowledged: its bytes leave the flight and
%% it is the one whose send time the window uses.
ack_of_a_padded_packet_removes_its_bytes_test() ->
    L0 = mixed(app, quic_loss:new(), 0),
    {L, [_], [], Meta} = quic_loss:on_ack_received(app, L0, {ack, 1, 0, 0, []}, 10),
    ?assertMatch(#{acked_bytes := 1200, has_in_flight := true, largest_acked_sent_time := 0}, Meta),
    ?assertEqual(1000, quic_loss:bytes_in_flight(L)).

%% An ACK-only packet declared lost leaves the queue (RFC 9002 Appendix
%% A.10) without touching the count it was never part of.
lost_ack_only_packet_leaves_the_queue_test() ->
    L0 = lists:foldl(
        fun(PN, Acc) -> quic_loss:on_packet_sent(app, Acc, PN, 1000, true, [ping], 0) end,
        quic_loss:on_packet_sent(app, quic_loss:new(), 0, 50, false, [ack()], 0),
        lists:seq(1, 4)
    ),
    {L, _Acked, Lost, Meta} = quic_loss:on_ack_received(app, L0, {ack, 4, 0, 0, []}, 10),
    ?assertMatch(
        [#sent_packet{pn = 0, in_flight = false}, #sent_packet{pn = 1, in_flight = true}],
        lists:keysort(#sent_packet.pn, Lost)
    ),
    ?assertEqual([2, 3], lists:sort(maps:keys(quic_loss:sent_packets(app, L)))),
    ?assertEqual(1000, maps:get(lost_bytes, Meta)),
    ?assertEqual(2000, quic_loss:bytes_in_flight(L)).

%% Discarding a space removes the bytes it added and no more, so the
%% other spaces keep theirs (RFC 9002 Appendix B.9).
discard_leaves_other_spaces_bytes_test() ->
    L0 = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 1000, true, [ping], 0),
    L1 = quic_loss:on_packet_sent(initial, L0, 0, 50, false, [ack()], 0),
    L2 = quic_loss:on_packet_sent(initial, L1, 1, 1200, true, [ping], 0),
    {L, Removed} = quic_loss:discard_space(initial, L2),
    ?assertEqual(1200, Removed),
    ?assertEqual(1000, quic_loss:bytes_in_flight(L)).

%%====================================================================
%% Connection
%%====================================================================

%% A client pads every Initial to 1200 bytes with PADDING frames, so its
%% ACK-only Initial is in flight and both counts carry it.
client_ack_only_initial_is_in_flight_test() ->
    S = ?S:state_sending(owing_initial_ack(?S:state_with_keys(client))),
    S1 = quic_connection:send_initial_ack(S),
    #sent_packet{ack_eliciting = false, in_flight = true, size = Size} = sent(initial, 0, loss(S1)),
    ?assertEqual(1200, Size),
    ?assertEqual({Size, Size}, counts(S1)).

%% It is still not congestion controlled (RFC 9002 Section 7): it goes out
%% with the window full.
padded_ack_only_initial_goes_out_with_a_full_window_test() ->
    CC = quic_cc:on_packet_sent(quic_cc:new(#{initial_window => 12000}), 12000),
    S = ?S:state_set(?S:state_sending(owing_initial_ack(?S:state_with_keys(client))), cc_state, CC),
    S1 = quic_connection:send_initial_ack(S),
    ?assertEqual(1, ?S:state_get(S1, initial_next_pn)),
    ?assertEqual([], ?S:pending_hs(S1, initial)),
    ?assertEqual(12000 + 1200, quic_cc:bytes_in_flight(?S:state_get(S1, cc_state))).

acknowledged_ack_only_initial_leaves_both_counts_test() ->
    S1 = quic_connection:send_initial_ack(?S:state_sending(owing_initial_ack(client()))),
    ?assertEqual({1200, 1200}, counts(S1)),
    S2 = quic_connection:process_frame(initial, {ack, [{0, 0}], 0, undefined}, S1),
    ?assertEqual({0, 0}, counts(S2)).

discarded_ack_only_initial_leaves_both_counts_test() ->
    S1 = quic_connection:send_initial_ack(?S:state_sending(owing_initial_ack(client()))),
    ?assertEqual({1200, 1200}, counts(S1)),
    S2 = quic_connection:discard_initial(S1),
    ?assertEqual({0, 0}, counts(S2)).

%% A 1-RTT packet too short for header protection gets PADDING, which
%% puts it in flight whatever else it carries.
padded_app_packet_is_in_flight_test() ->
    S = ?S:with_keys_and_socket(?S:state_for_role(client)),
    S1 = quic_connection:send_frame({connection_close, application, 0, undefined, <<>>}, S),
    [#sent_packet{ack_eliciting = false, in_flight = true, size = Size}] =
        maps:values(quic_loss:sent_packets(app, loss(S1))),
    ?assertEqual({Size, Size}, counts(S1)).

%%====================================================================
%% Helpers
%%====================================================================

ack() ->
    {ack, [{0, 0}], 0, undefined}.

%% An ack-eliciting packet of 1000 bytes, a padded ACK-only one of 1200
%% and a plain ACK-only one of 50, from FirstPN on.
mixed(Space, L0, FirstPN) ->
    L1 = quic_loss:on_packet_sent(Space, L0, FirstPN, 1000, true, true, [ping], 0),
    L2 = quic_loss:on_packet_sent(Space, L1, FirstPN + 1, 1200, false, true, [ack()], 0),
    quic_loss:on_packet_sent(Space, L2, FirstPN + 2, 50, false, false, [ack()], 0).

sent(Space, PN, L) ->
    maps:get(PN, quic_loss:sent_packets(Space, L)).

client() ->
    ?S:state_with_keys(client).

owing_initial_ack(S) ->
    ?S:state_set(S, initial_ack_ranges, [{0, 0}]).

loss(S) ->
    ?S:loss_state(S).

%% {loss tracker, congestion controller} bytes in flight.
counts(S) ->
    {quic_loss:bytes_in_flight(loss(S)), quic_cc:bytes_in_flight(?S:state_get(S, cc_state))}.
