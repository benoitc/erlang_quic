%%% -*- erlang -*-
%%%
%%% Every ack-eliciting packet waits for the congestion window (RFC 9002
%%% Section 7). The exceptions are a PTO probe (Section 7.5) and the one
%%% packet a sender may send on entering recovery (Section 7.3.2).
%%% Packets that are not in flight, ACK-only and CONNECTION_CLOSE, are
%%% never held back.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cwnd_admission_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(CWND, 12000).
-define(PKT, 1200).
%% Packets that fill the window in the in_flight/1 states.
-define(FLIGHT, 10).

%%====================================================================
%% No allowance above the window
%%====================================================================

%% Urgency 0 orders a stream first, it does not let it past the window.
urgency_zero_stream_waits_for_cwnd_test() ->
    S0 = full(quic_connection_test_support:state_with_send_windows([{0, 0, 1000000}], 1000000)),
    Out = quic_connection_test_support:datagrams_out(S0),
    {ok, S1} = quic_connection:do_send_data(0, <<"tick">>, false, S0, check),
    ?assertEqual(Out, quic_connection_test_support:datagrams_out(S1)),
    ?assertEqual([{0, 0, 4}], quic_connection_test_support:queued_entries(S1)),
    ?assertEqual(?CWND, quic_cc:bytes_in_flight(cc(S1))).

%% An HTTP/3 peer's u=0 (RFC 9218) reaches the stream through
%% set_stream_priority; it gets no more room than any other stream.
peer_priority_zero_waits_for_cwnd_test() ->
    S0 = full(quic_connection_test_support:state_with_send_windows([{0, 3, 1000000}], 1000000)),
    {ok, S1} = quic_connection:do_set_stream_priority(0, 0, false, S0),
    Out = quic_connection_test_support:datagrams_out(S1),
    {ok, S2} = quic_connection:do_send_data(0, <<"request">>, false, S1, check),
    ?assertEqual(Out, quic_connection_test_support:datagrams_out(S2)),
    ?assertEqual(?CWND, quic_cc:bytes_in_flight(cc(S2))).

%% A small Handshake packet with the window exactly full is held.
handshake_packet_waits_for_cwnd_test() ->
    S0 = quic_connection_test_support:state_set(
        full(
            quic_connection_test_support:state_sending(
                quic_connection_test_support:state_with_keys(server)
            )
        ),
        address_validated,
        true
    ),
    Frames = [{crypto, 0, <<"fin">>}],
    S1 = quic_connection:send_handshake_packet(<<6, 0, 3, "fin">>, Frames, S0),
    ?assertEqual(1, length(quic_connection_test_support:pending_hs(S1, handshake))),
    ?assertEqual(?CWND, quic_cc:bytes_in_flight(cc(S1))).

%% A queued retransmission is taken off the queue only when the packet
%% the send builds for it fits: the gate and the send agree.
retransmit_stream_gate_matches_the_send_test() ->
    Data = binary:copy(<<"r">>, 100),
    S0 = quic_connection_test_support:state_with_send_windows([{0, 3, 1000000}], 1000000),
    S1 = quic_connection:enqueue_retransmit_stream(0, 5000, Data, false, S0),
    %% send_retransmit_packet/3 sizes it as the frame plus 50 bytes.
    Size = iolist_size(quic_frame:encode({stream, 0, 5000, Data, false})) + 50,
    %% One byte short: left queued, untouched.
    Short = with_room(S1, Size - 1),
    Version = quic_connection_test_support:state_get(Short, send_queue_version),
    S2 = quic_connection:process_send_queue(Short),
    ?assertEqual(Version, quic_connection_test_support:state_get(S2, send_queue_version)),
    ?assertEqual([{0, 5000, 100}], quic_connection_test_support:queued_entries(S2)),
    %% Exactly enough: sent, and the window is then full.
    S3 = quic_connection:process_send_queue(with_room(S1, Size)),
    ?assertEqual([], quic_connection_test_support:queued_entries(S3)),
    CC3 = cc(S3),
    ?assert(quic_cc:bytes_in_flight(CC3) =< quic_cc:cwnd(CC3)).

%%====================================================================
%% Control frames wait for the window
%%====================================================================

%% Every control frame send_frame/2 sends is held while the window is
%% full, then goes out once an acknowledgement opens room.
control_frames_wait_for_cwnd_test_() ->
    [
        {atom_to_list(element(1, frame_name(F))), fun() -> control_frame_waits(F) end}
     || F <- control_frames()
    ].

control_frame_waits(Frame) ->
    S0 = in_flight(?FLIGHT),
    S1 = quic_connection:send_frame(Frame, S0),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual([Frame], held(S1)),
    ?assertEqual(?FLIGHT * ?PKT, quic_cc:bytes_in_flight(cc(S1))),
    S2 = ack_all(S1),
    ?assertEqual([], held(S2)),
    ?assertEqual([[Frame]], sent_frames(S2)).

%% Held frames go out in the order they were sent, before the stream data
%% that was queued behind them.
held_frames_go_in_order_before_stream_data_test() ->
    S0 = in_flight(?FLIGHT),
    Token = binary:copy(<<"t">>, 16),
    F1 = {new_connection_id, 1, 0, <<"cid-0001">>, Token},
    F2 = {retire_connection_id, 0},
    S1 = quic_connection:send_frame(F2, quic_connection:send_frame(F1, S0)),
    {ok, S2} = quic_connection:do_send_data(0, <<"data">>, false, S1, check),
    ?assertEqual(next_pn(S0), next_pn(S2)),
    ?assertEqual([F1, F2], held(S2)),
    S3 = ack_all(S2),
    ?assertEqual([[F1, F2], [{stream, 0, 0, <<"data">>, false}]], sent_frames(S3)).

%% quic:send_ping/1 queues its PING; a second one adds nothing.
send_ping_waits_for_cwnd_test() ->
    S0 = in_flight(?FLIGHT),
    S1 = call_send_ping(call_send_ping(S0)),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual([ping], held(S1)),
    ?assertEqual([[ping]], sent_frames(ack_all(S1))).

%% A PATH_RESPONSE with no source address to answer goes out as an
%% ordinary frame, and waits like one.
path_response_fallback_waits_for_cwnd_test() ->
    S0 = (in_flight(?FLIGHT))#state{current_packet_source = undefined},
    Data = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    S1 = quic_connection:process_frame(app, {path_challenge, Data}, S0),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual([{path_response, Data}], held(S1)).

%% The keep-alive PING is dropped: bytes are in flight, so the connection
%% is not idle.
keep_alive_ping_is_dropped_test() ->
    S0 = in_flight(?FLIGHT),
    S1 = quic_connection:send_keep_alive_ping(S0),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual([], held(S1)).

%% A DATAGRAM the window refuses is dropped, not held (RFC 9221 Section 5).
datagram_is_dropped_by_a_full_window_test() ->
    S0 = (in_flight(?FLIGHT))#state{max_datagram_frame_size_remote = 1200},
    ?assertMatch({error, congestion_limited, _}, quic_connection:do_send_datagram(<<"d">>, S0)),
    {error, congestion_limited, S1} = quic_connection:do_send_datagram(<<"d">>, S0),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual([], held(S1)).

%% The pacer refuses a DATAGRAM the same way.
datagram_is_dropped_by_the_pacer_test() ->
    S0 = paced_out((with_room(app_state(), ?CWND))#state{max_datagram_frame_size_remote = 4000}),
    Data = binary:copy(<<"d">>, 1000),
    {error, congestion_limited, S1} = quic_connection:do_send_datagram(Data, S0),
    ?assertEqual(next_pn(S0), next_pn(S1)).

%% An ACK-only packet is not in flight: it goes out and is not charged.
ack_only_goes_out_with_a_full_window_test() ->
    S0 = owing_ack(in_flight(?FLIGHT)),
    S1 = quic_connection:send_app_ack(S0),
    ?assertEqual(next_pn(S0) + 1, next_pn(S1)),
    ?assertEqual(?FLIGHT * ?PKT, quic_cc:bytes_in_flight(cc(S1))).

%% Nor is CONNECTION_CLOSE.
connection_close_goes_out_with_a_full_window_test() ->
    S0 = in_flight(?FLIGHT),
    S1 = quic_connection:send_frame({connection_close, transport, 0, 0, <<>>}, S0),
    ?assertEqual(next_pn(S0) + 1, next_pn(S1)),
    ?assertEqual(?FLIGHT * ?PKT, quic_cc:bytes_in_flight(cc(S1))).

%% Frames held while a server receive pass decides where the peer is go
%% through the same check when the pass ends.
pass_frames_wait_for_cwnd_test() ->
    S0 = (in_flight(?FLIGHT))#state{hold_pass_frames = true},
    Frame = {max_streams, bidi, S0#state.max_streams_bidi_local},
    S1 = quic_connection:send_pass_frames(quic_connection:send_frame(Frame, S0)),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual([Frame], held(S1)).

%% A control frame joining a coalesced packet is checked with the bytes
%% already pending in it.
control_frame_beside_pending_stream_data_test() ->
    Data = binary:copy(<<"s">>, 900),
    S0 = (with_room(app_state(), 955))#state{coalesce = true},
    {ok, S1} = quic_connection:do_send_data(0, Data, false, S0, check),
    Token = binary:copy(<<"t">>, 16),
    S2 = quic_connection:send_frame({new_connection_id, 1, 0, <<"cid-0001">>, Token}, S1),
    S3 = quic_connection:flush_pending_packet(S2),
    CC = cc(S3),
    ?assert(quic_cc:bytes_in_flight(CC) =< quic_cc:cwnd(CC)),
    ?assertMatch([{new_connection_id, 1, 0, _, _}], held(S3)).

%% A limit a newer one replaced while both were held is not sent.
superseded_limit_is_not_sent_test() ->
    S0 = in_flight(?FLIGHT),
    Max = S0#state.max_data_local,
    S1 = quic_connection:send_frame({max_data, Max}, S0),
    S2 = quic_connection:send_frame({max_data, Max + 1000}, S1#state{max_data_local = Max + 1000}),
    ?assertEqual([[{max_data, Max + 1000}]], sent_frames(ack_all(S2))).

%% The queue is bounded; past it the connection closes with INTERNAL_ERROR.
control_queue_overflow_closes_test() ->
    S0 = in_flight(?FLIGHT),
    Full = lists:duplicate(16384, {retire_connection_id, 0}),
    S1 = quic_connection:send_frame(
        {retire_connection_id, 1}, S0#state{ctrl_queue = {16384, queue:from_list(Full)}}
    ),
    ?assertMatch({transport, ?QUIC_INTERNAL_ERROR, _}, close_error(S1)).

%%====================================================================
%% Other paths into the window
%%====================================================================

%% Small stream data rides with an ACK only when the window has room for
%% it; otherwise the ACK goes alone and the data stays queued.
ack_with_small_stream_waits_for_cwnd_test() ->
    S0 = quic_connection_test_support:queue_stream(owing_ack(in_flight(?FLIGHT)), 0, 0, <<"x">>),
    S1 = quic_connection:send_app_ack(S0),
    ?assertEqual(next_pn(S0) + 1, next_pn(S1)),
    ?assertEqual(?FLIGHT * ?PKT, quic_cc:bytes_in_flight(cc(S1))),
    ?assertEqual([{0, 0, 1}], quic_connection_test_support:queued_entries(S1)).

ack_with_small_stream_rides_when_there_is_room_test() ->
    S0 = quic_connection_test_support:queue_stream(owing_ack(app_state()), 0, 0, <<"x">>),
    S1 = quic_connection:send_app_ack(S0),
    ?assertEqual(next_pn(S0) + 1, next_pn(S1)),
    ?assertEqual([], quic_connection_test_support:queued_entries(S1)),
    ?assert(quic_cc:bytes_in_flight(cc(S1)) > 0).

%% 0-RTT data waits for the window; what it holds back is queued and goes
%% out as 1-RTT.
zero_rtt_waits_for_cwnd_test() ->
    S0 = full(quic_connection_test_support:zero_rtt_client([0])),
    From = {self(), make_ref()},
    {keep_state, S1, [{reply, From, ok}]} =
        quic_connection:zero_rtt_sends([{From, 0, <<"early">>, false}], S0),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual(?CWND, quic_cc:bytes_in_flight(cc(S1))),
    ?assertMatch(
        {value, {retransmit_stream, 0, 0, <<"early">>, false, 5}},
        quic_connection_test_support:queue_head(S1)
    ).

%% Coalesced stream sends are checked with the bytes already pending.
coalesced_stream_sends_stay_within_cwnd_test() ->
    Data = binary:copy(<<"s">>, 600),
    S0 = (with_room(app_state(), 1000))#state{coalesce = true},
    {ok, S1} = quic_connection:do_send_data(0, Data, false, S0, check),
    {ok, S2} = quic_connection:do_send_data(0, Data, false, S1, check),
    CC = cc(quic_connection:flush_pending_packet(S2)),
    ?assert(quic_cc:bytes_in_flight(CC) =< quic_cc:cwnd(CC)).

%% A run of full chunks counts the first chunk against the window too.
chunk_run_stays_within_cwnd_test_() ->
    [
        {atom_to_list(P), fun() -> chunk_run_stays_within_cwnd(P) end}
     || P <- [pacing_off, pacing_on]
    ].

chunk_run_stays_within_cwnd(Pacing) ->
    S = app_state(),
    Chunk = quic_connection:get_max_stream_data_per_packet(S),
    S0 = pacing(Pacing, with_room(S, 2 * (Chunk + 50))),
    {ok, S1} = quic_connection:do_send_data(0, binary:copy(<<"c">>, 10 * Chunk), false, S0, check),
    CC = cc(S1),
    ?assert(next_pn(S1) > next_pn(S0)),
    ?assert(quic_cc:bytes_in_flight(CC) =< quic_cc:cwnd(CC)).

%%====================================================================
%% PTO probes
%%====================================================================

%% The probe goes out past the window, is charged, and carries the held
%% control frames (RFC 9002 Sections 6.2.4 and 7.5); the oldest packet's
%% PING needs no repair (RFC 9000 Section 13.3).
probe_carries_held_control_frames_test() ->
    S0 = in_flight(?FLIGHT),
    Token = binary:copy(<<"t">>, 16),
    F1 = {new_connection_id, 1, 0, <<"cid-0001">>, Token},
    F2 = {max_data, S0#state.max_data_local},
    S1 = quic_connection:send_frame(F2, quic_connection:send_frame(F1, S0)),
    S2 = quic_connection:handle_pto_timeout(S1#state{pto_space = app}),
    ?assertEqual([], held(S2)),
    ?assertEqual([[F1, F2]], [strip_immediate_ack(Fs) || Fs <- sent_frames(S2)]),
    ?assert(quic_cc:bytes_in_flight(cc(S2)) > quic_cc:cwnd(cc(S2))).

%% Held frames that do not fit the probe stay held, in order.
probe_leaves_what_does_not_fit_held_test() ->
    S0 = in_flight(?FLIGHT),
    Frames = [{new_token, binary:copy(<<N>>, 400)} || N <- lists:seq(1, 4)],
    S1 = lists:foldl(fun quic_connection:send_frame/2, S0, Frames),
    S2 = quic_connection:handle_pto_timeout(S1#state{pto_space = app}),
    [Sent] = [strip_immediate_ack(Fs) || Fs <- sent_frames(S2)],
    ?assertNotEqual([], Sent),
    ?assertNotEqual([], held(S2)),
    ?assertEqual(Frames, Sent ++ held(S2)).

%% A limit a newer one replaced is not what the probe resends.
probe_does_not_resend_a_superseded_limit_test() ->
    Old = 1000,
    S0 = in_flight(?FLIGHT, [{max_data, Old}]),
    S1 = S0#state{max_data_local = Old + 1000, pto_space = app},
    S2 = quic_connection:handle_pto_timeout(S1),
    ?assertEqual([[ping]], [strip_immediate_ack(Fs) || Fs <- sent_frames(S2)]).

%% Handshake data the window held back is what the Handshake probe sends.
handshake_probe_sends_what_the_window_held_test() ->
    S0 = quic_connection_test_support:state_set(
        full(
            quic_connection_test_support:state_sending(
                quic_connection_test_support:state_with_keys(server)
            )
        ),
        address_validated,
        true
    ),
    Frames = [{crypto, 0, <<"fin">>}],
    S1 = quic_connection:send_handshake_packet(<<6, 0, 3, "fin">>, Frames, S0),
    ?assertEqual(1, length(quic_connection_test_support:pending_hs(S1, handshake))),
    S2 = quic_connection:handle_pto_timeout(S1#state{pto_space = handshake}),
    ?assertEqual([], quic_connection_test_support:pending_hs(S2, handshake)),
    #state{loss_state = L} = S2,
    ?assertMatch(
        [#sent_packet{frames = Frames}], maps:values(quic_loss:sent_packets(handshake, L))
    ).

%% An application probe goes out with handshake packets still held.
app_probe_is_not_stranded_behind_handshake_data_test() ->
    S0 = in_flight(?FLIGHT),
    #state{hs = HS} = S0,
    Pending = queue:from_list([{<<6, 0, 3, "fin">>, [{crypto, 0, <<"fin">>}]}]),
    S1 = S0#state{
        pto_space = app,
        hs = HS#hs{pending_hs = #{initial => queue:new(), handshake => Pending}}
    },
    S2 = quic_connection:handle_pto_timeout(S1),
    ?assertEqual(next_pn(S1) + 1, next_pn(S2)).

%%====================================================================
%% Entering recovery (RFC 9002 Section 7.3.2)
%%====================================================================

%% The cut leaves the window below what is in flight. The first
%% retransmission goes out all the same; the second waits.
first_retransmission_goes_out_on_entering_recovery_test() ->
    S0 = in_flight_with(20, fun(PN) -> [{retire_connection_id, PN}] end),
    %% Packet 4 acknowledged: 0 and 1 are lost by the packet threshold.
    S1 = quic_connection:process_frame(app, {ack, [{4, 0}], 0, undefined}, S0),
    CC = cc(S1),
    ?assert(quic_cc:in_recovery(CC)),
    ?assert(quic_cc:bytes_in_flight(CC) > quic_cc:cwnd(CC)),
    [[Sent]] = [strip_immediate_ack(Fs) || Fs <- sent_frames_from(20, S1)],
    [Held] = held(S1),
    ?assertEqual(
        [{retire_connection_id, 0}, {retire_connection_id, 1}], lists:sort([Sent, Held])
    ).

%%====================================================================
%% Helpers
%%====================================================================

cc(State) ->
    quic_connection_test_support:state_get(State, cc_state).

%% The window exactly full.
full(State) ->
    with_room(State, 0).

%% A window with Room bytes left.
with_room(State, Room) ->
    CC = quic_cc:new(#{algorithm => newreno, initial_window => ?CWND}),
    quic_connection_test_support:state_set(
        State, cc_state, quic_cc:on_packet_sent(CC, ?CWND - Room)
    ).

%% A connected client with stream 0 open, coalescing and pacing off.
app_state() ->
    S = quic_connection_test_support:state_for_admission(0, 0, 1000000, 1000000),
    S#state{
        loss_state = quic_loss:on_handshake_confirmed(quic_loss:new()),
        owner = self(),
        transport_params = #{},
        max_data_local = 1000000,
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        max_streams_bidi_remote = 10,
        last_activity = erlang:monotonic_time(millisecond)
    }.

%% N tracked packets of ?PKT bytes in flight, filling a window of N packets.
in_flight(N) ->
    in_flight(N, [ping]).

%% The same, the oldest packet carrying OldestFrames.
in_flight(N, OldestFrames) ->
    in_flight_with(N, fun
        (0) -> OldestFrames;
        (_) -> [ping]
    end).

%% N packets in flight, packet PN carrying FramesOf(PN).
in_flight_with(N, FramesOf) ->
    S0 = app_state(),
    Sent = erlang:monotonic_time(millisecond) - 100,
    L = lists:foldl(
        fun(PN, Acc) -> quic_loss:on_packet_sent(app, Acc, PN, ?PKT, true, FramesOf(PN), Sent) end,
        S0#state.loss_state,
        lists:seq(0, N - 1)
    ),
    CC0 = quic_cc:new(#{algorithm => newreno, initial_window => N * ?PKT}),
    CC = lists:foldl(fun(_, Acc) -> quic_cc:on_packet_sent(Acc, ?PKT) end, CC0, lists:seq(1, N)),
    S0#state{loss_state = L, cc_state = CC, pn_app = (S0#state.pn_app)#pn_space{next_pn = N}}.

%% Acknowledge every packet sent so far, as the peer would.
ack_all(#state{pn_app = #pn_space{next_pn = Next}} = S) ->
    quic_connection:process_frame(app, {ack, [{Next - 1, Next - 1}], 0, undefined}, S).

%% Frames of each packet sent after the in_flight/1 flight, by packet
%% number, ACK frames left out.
sent_frames(State) ->
    sent_frames_from(?FLIGHT, State).

sent_frames_from(From, #state{loss_state = L}) ->
    Sent = quic_loss:sent_packets(app, L),
    [
        [F || F <- Fs, element(1, frame_name(F)) =/= ack]
     || {PN, #sent_packet{frames = Fs}} <- lists:sort(maps:to_list(Sent)), PN >= From
    ].

frame_name(F) when is_atom(F) -> {F};
frame_name(F) -> F.

held(#state{ctrl_queue = {N, Q}}) ->
    ?assertEqual(N, queue:len(Q)),
    queue:to_list(Q).

next_pn(#state{pn_app = #pn_space{next_pn = PN}}) -> PN.

close_error(#state{close_reason = R}) -> R.

owing_ack(#state{pn_app = PN} = S) ->
    S#state{
        pn_app = PN#pn_space{largest_recv = 4, recv_time = 0, ack_ranges = [{0, 4}]},
        ack_elicited_count = 1
    }.

call_send_ping(S) ->
    {keep_state, S1, _} = quic_connection:connected({call, {self(), make_ref()}}, send_ping, S),
    S1.

%% Pacing on, the bucket empty.
paced_out(#state{cfg = Cfg} = S) ->
    CC = spend(quic_cc:update_pacing_rate(cc(S), 3000)),
    S#state{cc_state = CC, cfg = Cfg#conn_cfg{pacing_enabled = true}}.

spend(CC) ->
    case quic_cc:send_check(CC, 1000) of
        {ok, CC1} -> spend(CC1);
        _ -> CC
    end.

control_frames() ->
    S = in_flight(?FLIGHT),
    Token = binary:copy(<<"t">>, 16),
    [
        {max_data, S#state.max_data_local},
        {max_stream_data, 0, 1000000},
        {max_streams, bidi, S#state.max_streams_bidi_local},
        {data_blocked, S#state.max_data_remote},
        {stream_data_blocked, 0, 1000000},
        {streams_blocked, bidi, S#state.max_streams_bidi_remote},
        {new_connection_id, 1, 0, <<"cid-0001">>, Token},
        {retire_connection_id, 0},
        {reset_stream, 0, 0, 0},
        {reset_stream_at, 4, 0, 10, 5},
        {stop_sending, 0, 0},
        handshake_done,
        {new_token, Token},
        {crypto, 0, <<"new-session-ticket">>},
        immediate_ack,
        ping,
        {path_response, <<1, 2, 3, 4, 5, 6, 7, 8>>}
    ].

pacing(pacing_off, S) ->
    S;
pacing(pacing_on, #state{cfg = Cfg} = S) ->
    S#state{cfg = Cfg#conn_cfg{pacing_enabled = true}}.

strip_immediate_ack(Frames) ->
    [F || F <- Frames, F =/= immediate_ack].
