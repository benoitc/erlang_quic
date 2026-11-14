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
%% Helpers
%%====================================================================

data(StreamId, Offset, Size) ->
    {stream, StreamId, Offset, binary:copy(<<StreamId>>, Size), false}.

%% Ranges acknowledging 4 and PN, PN below 3, once 0..1 were declared lost.
late(PN) ->
    [{4, 0}, {4 - PN - 2, 0}].

ack(State, Ranges) ->
    ack(app, State, Ranges).

ack(Level, State, Ranges) ->
    quic_connection:process_frame(Level, {ack, Ranges, 0, undefined}, State).

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
