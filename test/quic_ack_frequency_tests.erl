%%% -*- erlang -*-
%%%
%%% The QUIC ACK frequency extension (draft-ietf-quic-ack-frequency-14):
%%% the min_ack_delay transport parameter, the ACK_FREQUENCY and
%%% IMMEDIATE_ACK frames, and where a peer may send them.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_ack_frequency_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%%====================================================================
%% Frames (Sections 4 and 5)
%%====================================================================

ack_frequency_wire_format_test() ->
    %% Type 0xaf is a two-byte varint, then four varint fields.
    ?assertEqual(
        <<16#40, 16#af, 7, 10, 16#40, 16#c8, 3>>,
        quic_frame:encode({ack_frequency, 7, 10, 200, 3})
    ).

ack_frequency_roundtrip_test() ->
    Max = 16#3FFFFFFFFFFFFFFF,
    lists:foreach(
        fun(Frame) ->
            ?assertEqual({Frame, <<>>}, quic_frame:decode(quic_frame:encode(Frame)))
        end,
        [
            {ack_frequency, 0, 0, 1000, 0},
            {ack_frequency, 1, 1, 25000, 1},
            {ack_frequency, Max, Max, Max, Max}
        ]
    ).

immediate_ack_wire_format_test() ->
    ?assertEqual(<<16#1f>>, quic_frame:encode(immediate_ack)),
    ?assertEqual({immediate_ack, <<1>>}, quic_frame:decode(<<16#1f, 1>>)).

frames_decode_in_a_packet_test() ->
    Payload = iolist_to_binary([
        quic_frame:encode(immediate_ack),
        quic_frame:encode({ack_frequency, 2, 4, 5000, 3}),
        quic_frame:encode(ping)
    ]),
    ?assertEqual(
        {ok, [immediate_ack, {ack_frequency, 2, 4, 5000, 3}, ping]},
        quic_frame:decode_all(Payload)
    ).

truncated_ack_frequency_is_malformed_test() ->
    Full = quic_frame:encode({ack_frequency, 1, 2, 3000, 1}),
    lists:foreach(
        fun(Len) ->
            ?assertMatch(
                {error, {malformed, _}},
                quic_connection:decode_frame(binary:part(Full, 0, Len))
            )
        end,
        lists:seq(2, byte_size(Full) - 1)
    ).

ack_frequency_is_ack_eliciting_test() ->
    ?assert(quic_ack:is_ack_eliciting_frame({ack_frequency, 0, 1, 1000, 1})),
    ?assert(quic_ack:is_ack_eliciting_frame(immediate_ack)).

%%====================================================================
%% min_ack_delay transport parameter (Section 3)
%%====================================================================

min_ack_delay_roundtrip_test() ->
    Bin = quic_tls:encode_transport_params(#{min_ack_delay => 1000}),
    %% 0xff04de1b is an eight-byte varint id.
    ?assertEqual(<<16#c0, 0, 0, 0, 16#ff, 16#04, 16#de, 16#1b, 2, 16#43, 16#e8>>, Bin),
    ?assertEqual({ok, #{min_ack_delay => 1000}}, quic_tls:decode_transport_params(Bin)).

min_ack_delay_up_to_max_ack_delay_test() ->
    ?assertMatch(
        {ok, #{min_ack_delay := 10000}},
        decode(#{min_ack_delay => 10000, max_ack_delay => 10})
    ),
    %% max_ack_delay defaults to 25 ms.
    ?assertMatch({ok, #{min_ack_delay := 25000}}, decode(#{min_ack_delay => 25000})).

min_ack_delay_above_max_ack_delay_rejected_test() ->
    ?assertEqual(
        {error, {transport_parameter_error, min_ack_delay_too_large, 10001}},
        decode(#{min_ack_delay => 10001, max_ack_delay => 10})
    ),
    ?assertEqual(
        {error, {transport_parameter_error, min_ack_delay_too_large, 25001}},
        decode(#{min_ack_delay => 25001})
    ).

min_ack_delay_not_a_varint_rejected_test() ->
    Id = quic_varint:encode(16#ff04de1b),
    ?assertMatch(
        {error, _},
        quic_tls:decode_transport_params(<<Id/binary, 3, 16#43, 16#e8, 0>>)
    ),
    ?assertMatch({error, _}, quic_tls:decode_transport_params(<<Id/binary, 0>>)).

min_ack_delay_above_max_ack_delay_closes_test() ->
    %% Section 3: TRANSPORT_PARAMETER_ERROR, whichever role sent it.
    lists:foreach(
        fun(Role) ->
            S = quic_connection:apply_peer_transport_params(
                #{min_ack_delay => 30000}, quic_connection_test_support:state_for_role(Role)
            ),
            ?assertMatch(
                {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
                S#state.close_reason
            )
        end,
        [client, server]
    ).

min_ack_delay_is_not_remembered_test() ->
    %% Section 3: never kept for a later connection.
    ?assertEqual(
        #{max_idle_timeout => 30000},
        quic_connection:remembered_transport_params(#{
            max_idle_timeout => 30000, min_ack_delay => 1000
        })
    ).

%%====================================================================
%% Sender (Sections 4, 5 and 7)
%%====================================================================

sends_request_when_peer_advertised_test() ->
    S = quic_connection:request_ack_frequency({10, 50000, 3}, sender(#{min_ack_delay => 1000})),
    ?assertEqual([{ack_frequency, 0, 10, 50000, 3}], ack_frequency_frames(S)).

nothing_without_peer_min_ack_delay_test() ->
    S = quic_connection:request_ack_frequency({10, 50000, 3}, sender(#{})),
    ?assertEqual([], ack_frequency_frames(S)).

nothing_from_newreno_or_cubic_test_() ->
    [
        {atom_to_list(Algo), fun() ->
            S0 = sender(#{min_ack_delay => 1000}),
            S = quic_connection:maybe_request_ack_frequency(S0#state{
                cc_state = quic_cc:new(#{algorithm => Algo})
            }),
            ?assertEqual([], sent_frames(S))
        end}
     || Algo <- [newreno, cubic]
    ].

delay_kept_within_peer_bounds_test() ->
    S1 = quic_connection:request_ack_frequency({10, 500, 3}, sender(#{min_ack_delay => 2000})),
    ?assertEqual([{ack_frequency, 0, 10, 2000, 3}], ack_frequency_frames(S1)),
    S2 = quic_connection:request_ack_frequency({10, 1 bsl 40, 3}, sender(#{min_ack_delay => 2000})),
    ?assertEqual([{ack_frequency, 0, 10, 16383999, 3}], ack_frequency_frames(S2)).

the_default_is_not_requested_test() ->
    %% RFC 9000 Section 13.2 behaviour with the peer's max_ack_delay.
    S = quic_connection:request_ack_frequency(
        {1, 20000, 1}, sender(#{min_ack_delay => 1000, max_ack_delay => 20})
    ),
    ?assertEqual([], ack_frequency_frames(S)).

sequence_numbers_increase_test() ->
    S0 = sender(#{min_ack_delay => 1000}),
    S1 = quic_connection:request_ack_frequency({10, 50000, 3}, S0),
    %% Same request: nothing new.
    S2 = quic_connection:request_ack_frequency({10, 50000, 3}, S1),
    %% More frequent: at once.
    S3 = quic_connection:request_ack_frequency({1, 10000, 1}, S2),
    ?assertEqual(
        [{ack_frequency, 0, 10, 50000, 3}, {ack_frequency, 1, 1, 10000, 1}],
        ack_frequency_frames(S3)
    ).

fewer_acks_at_most_once_per_rtt_test() ->
    S1 = quic_connection:request_ack_frequency({2, 10000, 1}, sender(#{min_ack_delay => 1000})),
    S2 = quic_connection:request_ack_frequency({8, 40000, 3}, S1),
    ?assertEqual(1, length(ack_frequency_frames(S2))),
    %% One smoothed RTT later.
    Req = S2#state.ack_freq_req,
    S3 = quic_connection:request_ack_frequency({8, 40000, 3}, S2#state{
        ack_freq_req = Req#ack_freq_req{sent_at = Req#ack_freq_req.sent_at - 1000}
    }),
    ?assertMatch([_, {ack_frequency, 1, 8, 40000, 3}], ack_frequency_frames(S3)).

pto_uses_a_larger_delay_at_once_test() ->
    S = quic_connection:request_ack_frequency({10, 50000, 3}, sender(#{min_ack_delay => 1000})),
    ?assertEqual(50, quic_loss:max_ack_delay(S#state.loss_state)).

pto_takes_a_smaller_delay_once_acknowledged_test() ->
    %% Section 7: the larger of the current and in-flight values.
    S1 = quic_connection:request_ack_frequency({10, 50000, 3}, sender(#{min_ack_delay => 1000})),
    S2 = quic_connection:request_ack_frequency({1, 4500, 1}, S1),
    ?assertEqual(50, quic_loss:max_ack_delay(S2#state.loss_state)),
    [_, Second] = [P || P <- sent(S2), lists:keymember(ack_frequency, 1, P#sent_packet.frames)],
    [First, _] = [P || P <- sent(S2), lists:keymember(ack_frequency, 1, P#sent_packet.frames)],
    S3 = quic_connection:ack_frequency_acked([First], S2),
    ?assertEqual(50, quic_loss:max_ack_delay(S3#state.loss_state)),
    S4 = quic_connection:ack_frequency_acked([Second], S3),
    ?assertEqual(5, quic_loss:max_ack_delay(S4#state.loss_state)).

only_the_latest_request_is_resent_test() ->
    S1 = quic_connection:request_ack_frequency({10, 50000, 3}, sender(#{min_ack_delay => 1000})),
    ?assert(quic_connection:is_current_limit({ack_frequency, 0, 10, 50000, 3}, S1)),
    S2 = quic_connection:request_ack_frequency({1, 4000, 1}, S1),
    ?assertNot(quic_connection:is_current_limit({ack_frequency, 0, 10, 50000, 3}, S2)),
    ?assert(quic_connection:is_current_limit({ack_frequency, 1, 1, 4000, 1}, S2)).

immediate_ack_is_not_retransmitted_test() ->
    ?assertEqual([ping], quic_loss:retransmittable_frames([immediate_ack, ping])).

immediate_ack_on_the_flight_end_test() ->
    meck:new(quic_cc, [passthrough]),
    try
        meck:expect(quic_cc, immediate_ack, 1, true),
        %% Nothing queued: this packet ends the flight.
        S = quic_connection:send_frame(ping, sender(#{min_ack_delay => 1000})),
        ?assertEqual([[ping, immediate_ack]], [P#sent_packet.frames || P <- sent(S)]),
        %% More queued and room in the window: it does not.
        S1 = sender(#{min_ack_delay => 1000}),
        S2 = quic_connection:send_frame(ping, S1#state{send_queue_count = 1}),
        ?assertEqual([[ping]], [P#sent_packet.frames || P <- sent(S2)]),
        %% Never to a peer without min_ack_delay.
        S3 = quic_connection:send_frame(ping, sender(#{})),
        ?assertEqual([[ping]], [P#sent_packet.frames || P <- sent(S3)])
    after
        meck:unload(quic_cc)
    end.

no_immediate_ack_unless_asked_test() ->
    S = quic_connection:send_frame(ping, sender(#{min_ack_delay => 1000})),
    ?assertEqual([[ping]], [P#sent_packet.frames || P <- sent(S)]).

%%====================================================================
%% Where the frames may appear
%%====================================================================

not_in_long_header_or_zero_rtt_test_() ->
    [
        {lists:flatten(io_lib:format("~p in ~p", [name(Frame), Level])), fun() ->
            ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, close(Level, Frame))
        end}
     || Level <- [initial, handshake, zero_rtt],
        Frame <- [{ack_frequency, 0, 1, 1000, 1}, immediate_ack]
    ].

%% A connected receiver that can send ACKs and has received nothing yet.
receiver() ->
    S = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(client)
    ),
    S#state{
        pn_app = #pn_space{
            next_pn = 0,
            largest_recv = undefined,
            recv_time = undefined,
            ack_ranges = [],
            ack_eliciting_in_flight = 0
        }
    }.

%% Receive each {PN, Frames} as a 1-RTT packet; yes where it sent an ACK.
acks(S, Packets) ->
    element(1, run(S, Packets)).

run(S0, Packets) ->
    lists:mapfoldl(
        fun({PN, Frames}, Acc) ->
            Before = acks_sent(Acc),
            Now = erlang:monotonic_time(millisecond),
            Acc1 = quic_connection:record_received_pn(app, PN, Acc, Now),
            Acc2 = lists:foldl(fun(F, A) -> process(app, F, A) end, Acc1, Frames),
            Acc3 = quic_connection:maybe_send_ack(app, Frames, Acc2),
            {
                case acks_sent(Acc3) - Before of
                    0 -> no;
                    1 -> yes
                end,
                Acc3
            }
        end,
        S0,
        Packets
    ).

%% A connected sender whose peer sent TP, packets going straight out.
sender(TP) ->
    S = receiver(),
    S#state{coalesce = false, transport_params = TP}.

sent(#state{loss_state = LS}) ->
    [P || {_, P} <- lists:sort(maps:to_list(quic_loss:sent_packets(app, LS)))].

sent_frames(S) ->
    lists:append([P#sent_packet.frames || P <- sent(S)]).

ack_frequency_frames(S) ->
    [F || {ack_frequency, _, _, _, _} = F <- sent_frames(S)].

acks_sent(S) ->
    quic_connection:count(?C_ACK_SENT, S).

decode(Params) ->
    quic_tls:decode_transport_params(quic_tls:encode_transport_params(Params)).

name(Frame) when is_tuple(Frame) -> element(1, Frame);
name(Frame) -> Frame.

close(Level, Frame) ->
    (process(Level, Frame, server_state()))#state.close_reason.

process(Level, Frame, S0) ->
    quic_connection:process_frame_track_probing(Level, Frame, S0).

server_state() ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    #state{hs = HS} = S0,
    S0#state{hs = HS#hs{pn_initial = HS#hs.pn_handshake}}.

%% We always advertise min_ack_delay, so both frames are accepted in 1-RTT.
accepted_in_one_rtt_test_() ->
    [
        {atom_to_list(name(Frame)), fun() ->
            ?assertEqual(undefined, close(app, Frame))
        end}
     || Frame <- [{ack_frequency, 0, 1, 1000, 1}, immediate_ack]
    ].

%%====================================================================
%% Receiver (Sections 3, 4, 5 and 6)
%%====================================================================

advertises_min_ack_delay_test() ->
    ?assertEqual(#{min_ack_delay => 1000}, quic_connection:with_min_ack_delay(#{})).

requested_max_ack_delay_bounds_test_() ->
    [
        {integer_to_list(Delay), fun() ->
            S = process(app, {ack_frequency, 0, 1, Delay, 1}, receiver()),
            case Valid of
                true ->
                    ?assertEqual(undefined, S#state.close_reason),
                    ?assertEqual(Delay div 1000, quic_connection:ack_delay_ms(S));
                false ->
                    ?assertMatch(
                        {transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason
                    )
            end
        end}
     || {Delay, Valid} <- [
            {0, false}, {999, false}, {1000, true}, {16383999, true}, {16384000, false}
        ]
    ].

stale_sequence_numbers_ignored_test() ->
    S1 = process(app, {ack_frequency, 5, 9, 4000, 1}, receiver()),
    ?assertEqual(10, quic_connection:ack_tolerance(S1)),
    S2 = process(app, {ack_frequency, 3, 1, 2000, 1}, S1),
    S3 = process(app, {ack_frequency, 5, 1, 2000, 1}, S2),
    ?assertEqual(10, quic_connection:ack_tolerance(S3)),
    ?assertEqual(4, quic_connection:ack_delay_ms(S3)),
    S4 = process(app, {ack_frequency, 6, 0, 2000, 1}, S3),
    ?assertEqual(1, quic_connection:ack_tolerance(S4)),
    ?assertEqual(2, quic_connection:ack_delay_ms(S4)).

threshold_is_capped_test() ->
    S = process(app, {ack_frequency, 0, 1 bsl 40, 25000, 1}, receiver()),
    ?assertEqual(65, quic_connection:ack_tolerance(S)).

default_acks_every_second_packet_test() ->
    ?assertEqual([no, yes, no, yes], acks(receiver(), [{N, [ping]} || N <- lists:seq(0, 3)])).

threshold_delays_the_ack_test() ->
    %% Section 6: an ACK once more than Ack-Eliciting Threshold packets arrived.
    S = process(app, {ack_frequency, 0, 3, 25000, 1}, receiver()),
    ?assertEqual(
        [no, no, no, yes, no],
        acks(S, [{N, [ping]} || N <- lists:seq(0, 4)])
    ).

threshold_zero_acks_every_packet_test() ->
    S = process(app, {ack_frequency, 0, 0, 25000, 1}, receiver()),
    ?assertEqual([yes, yes, yes], acks(S, [{N, [ping]} || N <- lists:seq(0, 2)])).

timer_uses_requested_max_ack_delay_test() ->
    S0 = process(app, {ack_frequency, 0, 9, 3000, 1}, receiver()),
    S = quic_connection:arm_ack_timer(S0),
    Left = erlang:read_timer(S#state.ack_timer),
    ?assert(is_integer(Left) andalso Left =< 3).

shorter_delay_drops_an_armed_timer_test() ->
    S0 = quic_connection:arm_ack_timer(receiver()),
    Timer = S0#state.ack_timer,
    S = process(app, {ack_frequency, 0, 1, 2000, 1}, S0),
    ?assertEqual(undefined, S#state.ack_timer),
    ?assertEqual(false, erlang:read_timer(Timer)).

immediate_ack_acks_at_once_test() ->
    S = process(app, {ack_frequency, 0, 9, 25000, 1}, receiver()),
    ?assertEqual(
        [no, yes, no],
        acks(S, [{0, [ping]}, {1, [ping, immediate_ack]}, {2, [ping]}])
    ),
    %% Alone in a packet, and without any ACK_FREQUENCY before it.
    ?assertEqual([yes], acks(receiver(), [{0, [immediate_ack]}])).

immediate_ack_in_a_sequential_run_test() ->
    S0 = process(app, {ack_frequency, 0, 9, 25000, 1}, receiver()),
    %% The run's receive bookkeeping is done before its frames.
    {_, S1} = run(S0, [{N, []} || N <- [0, 1, 2]]),
    S = quic_connection:fold_opened_seq(
        [{0, 16#40, [ping]}, {1, 16#40, [ping, immediate_ack]}, {2, 16#40, [ping]}], S1, 0, 0
    ),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual(1, acks_sent(S)),
    ?assertEqual(1, S#state.ack_elicited_count).

reordering_threshold_one_is_the_default_test() ->
    %% RFC 9000 Section 13.2.1: a packet above a gap is acknowledged at once.
    S = process(app, {ack_frequency, 0, 9, 25000, 1}, receiver()),
    ?assertEqual([no, yes], acks(S, [{0, [ping]}, {2, [ping]}])),
    ?assertEqual([no, yes], acks(receiver(), [{0, [ping]}, {2, [ping]}])).

reordering_threshold_zero_test() ->
    %% Section 6.2: out-of-order packets do not ACK at once.
    S = process(app, {ack_frequency, 0, 9, 25000, 0}, receiver()),
    ?assertEqual([no, no, no], acks(S, [{0, [ping]}, {3, [ping]}, {1, [ping]}])).

reordering_threshold_three_test() ->
    %% Section 6.2.1, Table 1: ACKs on packets 5, 9 and 10.
    S = process(app, {ack_frequency, 0, 100, 25000, 3}, receiver()),
    ?assertEqual(
        [no, no, no, no, yes, no, yes, yes],
        acks(S, [{N, [ping]} || N <- [0, 1, 3, 4, 5, 8, 9, 10]])
    ).

reordering_threshold_five_test() ->
    %% Section 6.2.1, Table 2: ACKs on packets 7 and 9.
    S = process(app, {ack_frequency, 0, 100, 25000, 5}, receiver()),
    ?assertEqual(
        [no, no, no, no, no, yes, no, yes],
        acks(S, [{N, [ping]} || N <- [0, 1, 3, 5, 6, 7, 8, 9]])
    ).

late_packet_already_reported_missing_test() ->
    %% Section 6.2, second condition: at or below Largest Acked - threshold.
    S0 = process(app, {ack_frequency, 0, 100, 25000, 3}, receiver()),
    {[no, no, no, yes], S1} = run(S0, [{N, [ping]} || N <- [0, 2, 3, 4]]),
    ?assertEqual([yes], acks(S1, [{1, [ping]}])),
    %% Within the window: no ACK.
    S2 = process(app, {ack_frequency, 0, 4, 25000, 3}, receiver()),
    {[no, no, no, no, yes], S3} = run(S2, [{N, [ping]} || N <- [0, 1, 2, 4, 5]]),
    ?assertEqual([no], acks(S3, [{3, [ping]}])).
