%%% -*- erlang -*-
%%%
%%% RFC 9000 Section 13.3: a sender stops resending what a packet carried
%%% once the packet is acknowledged, also when the acknowledgement comes
%%% after the packet was declared lost.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_late_ack_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).
-define(PKT, 1200).
%% Packets in flight at the start, filling the window.
-define(FLIGHT, 20).

%%====================================================================
%% The acknowledgement takes effect
%%====================================================================

%% The data was acknowledged and the FIN-only packet arrives late while
%% its copy is held: the send side is done without waiting for the copy.
late_ack_of_the_fin_completes_the_send_side_test() ->
    Fin = {stream, 0, 100, <<>>, true},
    S0 = with_fin_sent(
        100, in_flight(#{0 => [data(0, 0, 100)], 1 => [Fin], 2 => [{retire_connection_id, 0}]})
    ),
    %% 0 and 5 acknowledged: 1 and 2 are lost, 2's frame goes out on
    %% entering recovery and the FIN is held.
    S1 = ack(S0, [{5, 0}, {3, 0}]),
    ?assertEqual([{0, 100, 0}], ?S:queued_entries(S1)),
    ?assertNot(send_done(S1)),
    S2 = ack(S1, [{5, 0}, {2, 1}]),
    ?assert(send_done(S2)).

%% An ACK_FREQUENCY acknowledged late lowers the PTO's max_ack_delay at
%% once rather than when its copy is.
late_ack_of_ack_frequency_counts_test() ->
    Request = {ack_frequency, 0, 1, 5000, 1},
    S0 = with_ack_frequency_request(Request, in_flight(#{0 => [Request]})),
    S1 = ack(S0, [{4, 0}]),
    #{?FLIGHT := #sent_packet{frames = [Request | _]}} = quic_loss:sent_packets(
        app, S1#state.loss_state
    ),
    ?assertEqual(25, quic_loss:max_ack_delay(S1#state.loss_state)),
    S2 = ack(S1, late(0)),
    ?assertEqual(5, quic_loss:max_ack_delay(S2#state.loss_state)).

%%====================================================================
%% Queued stream data
%%====================================================================

%% 0 and 1 are lost; 1's data goes out on entering recovery and 0's is
%% held. 0 then arrives late: its held copy is dropped and never sent,
%% while another held copy goes out once the window opens.
late_ack_drops_the_queued_stream_copy_test() ->
    S0 = in_flight(#{0 => [data(0, 0, 100)], 1 => [data(0, 100, 100)]}),
    S1 = hold(0, 500, 100, ack(S0, [{4, 0}])),
    ?assertEqual([{0, 0, 100}, {0, 500, 100}], lists:sort(?S:queued_entries(S1))),
    ?assertEqual({200, 2}, queue_counters(S1)),
    S2 = ack(S1, late(0)),
    ?assertEqual([{0, 500, 100}], ?S:queued_entries(S2)),
    ?assertEqual({100, 1}, queue_counters(S2)),
    S3 = ack_all(S2),
    ?assertEqual([], ?S:queued_entries(S3)),
    ?assertEqual([{0, 500, 100}], stream_frames_sent(next_pn(S2), S3)).

%% The packet carrying the stream's last data and FIN arrives late while
%% its copy is held: the copy goes and the send side is done.
late_ack_of_a_held_fin_completes_the_send_side_test() ->
    Last = {stream, 0, 0, binary:copy(<<0>>, 100), true},
    S0 = with_fin_sent(100, in_flight(#{0 => [Last], 1 => [{retire_connection_id, 0}]})),
    S1 = ack(S0, [{4, 0}]),
    ?assertEqual([{0, 0, 100}], ?S:queued_entries(S1)),
    ?assertNot(send_done(S1)),
    S2 = ack(S1, late(0)),
    ?assertEqual([], ?S:queued_entries(S2)),
    ?assert(send_done(S2)).

%% A late acknowledgement covering part of a held copy leaves the rest.
late_ack_trims_a_partly_covered_copy_test() ->
    S0 = in_flight(#{0 => [data(0, 0, 300)], 1 => [data(0, 100, 100)]}),
    S1 = ack(S0, [{4, 0}]),
    ?assertEqual([{0, 0, 300}], ?S:queued_entries(S1)),
    S2 = ack(S1, late(1)),
    ?assertEqual([{0, 0, 100}, {0, 200, 100}], ?S:queued_entries(S2)),
    ?assertEqual({200, 2}, queue_counters(S2)),
    %% Everything but 0 acknowledged: the window opens, the rest goes out.
    S3 = ack(S2, [{next_pn(S2) - 1, next_pn(S2) - 2}]),
    ?assertEqual([{0, 0, 100}, {0, 200, 100}], stream_frames_sent(next_pn(S2), S3)).

%% Copies of another stream, or of a range not acknowledged, stay held.
late_ack_keeps_other_copies_test() ->
    S0 = in_flight(#{0 => [data(0, 0, 100)], 1 => [data(0, 300, 100)]}),
    S3 = hold(4, 0, 100, hold(0, 500, 100, ack(S0, [{4, 0}]))),
    ?assertEqual([{0, 0, 100}, {0, 500, 100}, {4, 0, 100}], lists:sort(?S:queued_entries(S3))),
    S4 = ack(S3, late(0)),
    ?assertEqual([{0, 500, 100}, {4, 0, 100}], lists:sort(?S:queued_entries(S4))),
    ?assertEqual({200, 2}, queue_counters(S4)).

%%====================================================================
%% Held control frames
%%====================================================================

%% A held NEW_CONNECTION_ID is dropped when its lost packet arrives late;
%% the frame held behind it still goes out.
late_ack_drops_the_held_control_frame_test() ->
    Token = binary:copy(<<"t">>, 16),
    NewCid = {new_connection_id, 1, 0, <<"cid-0001">>, Token},
    S0 = in_flight(#{0 => [NewCid], 1 => [{retire_connection_id, 0}]}),
    S1 = ack(S0, [{4, 0}]),
    MaxData = {max_data, S1#state.max_data_local},
    S2 = quic_connection:send_frame(MaxData, S1),
    ?assertEqual([NewCid, MaxData], held(S2)),
    S3 = ack(S2, late(0)),
    ?assertEqual([MaxData], held(S3)),
    S4 = ack_all(S3),
    ?assertEqual([], held(S4)),
    ?assertEqual([[MaxData]], control_frames_sent(next_pn(S3), S4)).

%%====================================================================
%% Held handshake packets
%%====================================================================

%% A Handshake packet held for the window is dropped once the CRYPTO it
%% repairs is acknowledged.
late_ack_drops_the_held_handshake_packet_test() ->
    S0 = handshake_in_flight(#{0 => [crypto(0, 100)], 1 => [crypto(100, 100)]}),
    S1 = ack(handshake, S0, [{4, 0}]),
    ?assertMatch([{_, [{crypto, 0, _}]}], ?S:pending_hs(S1, handshake)),
    ?assert(pending_hs_bytes(S1) > 0),
    S2 = ack(handshake, S1, late(0)),
    ?assertEqual([], ?S:pending_hs(S2, handshake)),
    ?assertEqual(0, pending_hs_bytes(S2)).

%%====================================================================
%% What a copy keeps
%%====================================================================

%% The FIN stays on the piece that ends at it.
fin_stays_on_the_last_piece_test() ->
    Copy = {stream, 0, 0, binary:copy(<<0>>, 300), true},
    ?assertMatch(
        [{stream, 0, 0, <<_:100/binary>>, false}, {stream, 0, 200, <<_:100/binary>>, true}],
        drop_acked([Copy], [[data(0, 100, 100)]])
    ).

%% Data acknowledged without the FIN leaves a FIN-only copy.
acknowledged_data_leaves_the_fin_owed_test() ->
    Copy = {stream, 0, 200, binary:copy(<<0>>, 100), true},
    ?assertEqual([{stream, 0, 300, <<>>, true}], drop_acked([Copy], [[data(0, 0, 300)]])).

%% A FIN-only copy goes once the FIN is acknowledged, not before.
fin_only_copy_goes_with_the_fin_test() ->
    Copy = {stream, 0, 300, <<>>, true},
    ?assertEqual([Copy], drop_acked([Copy], [[data(0, 0, 300)]])),
    Fin = {stream, 0, 200, binary:copy(<<0>>, 100), true},
    ?assertEqual([], drop_acked([Copy], [[Fin]])).

%% CRYPTO keeps its unacknowledged ranges; other frames go only when equal.
crypto_and_control_copies_test() ->
    Acked = [[crypto(100, 100), {max_data, 5000}], [crypto(300, 50)]],
    ?assertMatch(
        [
            {crypto, 0, <<_:100/binary>>},
            {crypto, 200, <<_:100/binary>>},
            {crypto, 350, <<_:50/binary>>},
            {max_data, 6000}
        ],
        drop_acked([crypto(0, 400), {max_data, 5000}, {max_data, 6000}], Acked)
    ).

%%====================================================================
%% Helpers
%%====================================================================

%% A retransmission held in the send queue.
hold(StreamId, Offset, Size, State) ->
    {stream, _, _, Data, Fin} = data(StreamId, Offset, Size),
    quic_connection:enqueue_retransmit_stream(StreamId, Offset, Data, Fin, State).

drop_acked(Frames, Acked) ->
    quic_connection:drop_acked(Frames, quic_connection:acked_index(Acked)).

data(StreamId, Offset, Size) ->
    {stream, StreamId, Offset, binary:copy(<<StreamId>>, Size), false}.

crypto(Offset, Size) ->
    {crypto, Offset, binary:copy(<<"c">>, Size)}.

%% Ranges acknowledging 4 and PN, PN below 3, once 0..1 were declared lost.
late(PN) ->
    [{4, 0}, {4 - PN - 2, 0}].

ack(State, Ranges) ->
    ack(app, State, Ranges).

ack(Level, State, Ranges) ->
    quic_connection:process_frame(Level, {ack, Ranges, 0, undefined}, State).

%% Acknowledge every packet sent so far, as the peer would.
ack_all(#state{pn_app = #pn_space{next_pn = Next}} = S) ->
    ack(S, [{Next - 1, Next - 1}]).

queue_counters(#state{send_queue_bytes = Bytes, send_queue_count = Count}) ->
    {Bytes, Count}.

held(#state{ctrl_queue = {N, Q}}) ->
    ?assertEqual(N, queue:len(Q)),
    queue:to_list(Q).

next_pn(#state{pn_app = #pn_space{next_pn = PN}}) -> PN.

pending_hs_bytes(#state{hs = #hs{pending_hs_bytes = Bytes}}) ->
    maps:get(handshake, Bytes, 0).

%% {StreamId, Offset, Size} of the STREAM frames in packets from From on,
%% sorted.
stream_frames_sent(From, State) ->
    lists:sort([
        {Sid, Off, iolist_size(D)}
     || Fs <- frames_from(From, State), {stream, Sid, Off, D, _} <- Fs
    ]).

%% Frames of each packet from From on, without ACK and IMMEDIATE_ACK.
control_frames_sent(From, State) ->
    [
        [F || F <- Fs, element(1, frame_name(F)) =/= ack, F =/= immediate_ack]
     || Fs <- frames_from(From, State)
    ].

frames_from(From, #state{loss_state = L}) ->
    [
        Fs
     || {PN, #sent_packet{frames = Fs}} <- lists:sort(maps:to_list(quic_loss:sent_packets(app, L))),
        PN >= From
    ].

frame_name(F) when is_atom(F) -> {F};
frame_name(F) -> F.

%% A connected client with stream 0 open, coalescing and pacing off.
app_state() ->
    S = ?S:state_for_admission(0, 0, 1000000, 1000000),
    S#state{
        loss_state = quic_loss:on_handshake_confirmed(quic_loss:new()),
        owner = self(),
        transport_params = #{},
        max_data_local = 1000000,
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        max_streams_bidi_remote = 10,
        %% Sequence 1 issued, for the NEW_CONNECTION_ID frames sent below.
        cid_pool_state = element(1, quic_cid:issue(quic_cid:new(<<"own-cid0">>, 2), 1, undefined)),
        last_activity = erlang:monotonic_time(millisecond)
    }.

%% ?FLIGHT application packets filling the window, packet PN carrying the
%% frames Frames maps it to, a PING otherwise.
in_flight(Frames) ->
    S0 = app_state(),
    {L, CC} = flight(app, S0#state.loss_state, Frames),
    S0#state{loss_state = L, cc_state = CC, pn_app = (S0#state.pn_app)#pn_space{next_pn = ?FLIGHT}}.

%% The same in the Handshake space, for a server whose address is valid.
handshake_in_flight(Frames) ->
    S0 = ?S:state_set(?S:state_sending(?S:state_with_keys(server)), address_validated, true),
    {L, CC} = flight(handshake, S0#state.loss_state, Frames),
    HS = S0#state.hs,
    S0#state{
        loss_state = L,
        cc_state = CC,
        coalesce = false,
        hs = HS#hs{pn_handshake = (HS#hs.pn_handshake)#pn_space{next_pn = ?FLIGHT}}
    }.

flight(Space, L0, Frames) ->
    Sent = erlang:monotonic_time(millisecond) - 100,
    L = lists:foldl(
        fun(PN, Acc) ->
            quic_loss:on_packet_sent(Space, Acc, PN, ?PKT, true, maps:get(PN, Frames, [ping]), Sent)
        end,
        L0,
        lists:seq(0, ?FLIGHT - 1)
    ),
    CC0 = quic_cc:new(#{algorithm => newreno, initial_window => ?FLIGHT * ?PKT}),
    CC = lists:foldl(
        fun(_, Acc) -> quic_cc:on_packet_sent(Acc, ?PKT) end, CC0, lists:seq(1, ?FLIGHT)
    ),
    {L, CC}.

%% Stream 0 with Size bytes and its FIN sent.
with_fin_sent(Size, #state{streams = #{0 := Stream} = Streams} = S) ->
    S#state{
        streams = Streams#{
            0 := Stream#stream_state{send_offset = Size, send_highest = Size, send_fin = true}
        }
    }.

send_done(#state{streams = #{0 := #stream_state{send_done = Done}}}) -> Done.

%% Request sent, a 5 ms max_ack_delay pending its acknowledgement.
with_ack_frequency_request({ack_frequency, Seq, Threshold, Delay, Reordering}, S) ->
    S#state{
        ack_freq_req = #ack_freq_req{
            seq = Seq,
            threshold = Threshold,
            max_ack_delay = Delay,
            reordering = Reordering,
            sent_at = erlang:monotonic_time(millisecond),
            pending_pto_delay = Delay div 1000
        }
    }.
