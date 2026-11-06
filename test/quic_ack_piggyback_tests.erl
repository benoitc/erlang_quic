%% A pending ACK rides on the next ack-eliciting 1-RTT packet when it
%% fits the data budget (RFC 9000 §13.2.1), so a request/response
%% exchange sends no ACK-only packets.
-module(quic_ack_piggyback_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(S, quic_connection_test_support).

send(Payload, Frames, State) ->
    quic_connection:send_app_packet_internal(Payload, Frames, State).

small_stream() ->
    Frame = {stream, 0, 0, <<"request">>, false},
    {quic_frame:encode(Frame), [Frame]}.

last_sent_frames(State) ->
    Sent = quic_loss:sent_packets(app, ?S:loss_state(State)),
    #sent_packet{frames = Frames} = maps:get(lists:max(maps:keys(Sent)), Sent),
    Frames.

owed_ack_rides_on_data_test() ->
    {Payload, Frames} = small_stream(),
    S1 = send(Payload, Frames, ?S:state_owing_ack(1, true)),
    ?assertMatch([{ack, _, _, _}, {stream, 0, 0, <<"request">>, false}], last_sent_frames(S1)),
    ?assertMatch(
        #{ack_sent := 1, ack_elicited_count := 0, ack_timer := undefined}, ?S:ack_counters(S1)
    ).

timer_alone_is_enough_test() ->
    %% A datagram-only packet arms the timer without counting.
    {Payload, Frames} = small_stream(),
    S1 = send(Payload, Frames, ?S:state_owing_ack(0, true)),
    ?assertMatch([{ack, _, _, _} | _], last_sent_frames(S1)),
    ?assertMatch(#{ack_sent := 1, ack_timer := undefined}, ?S:ack_counters(S1)).

nothing_owed_sends_data_only_test() ->
    {Payload, Frames} = small_stream(),
    S1 = send(Payload, Frames, ?S:state_owing_ack(0, false)),
    ?assertEqual(Frames, last_sent_frames(S1)),
    ?assertMatch(#{ack_sent := 0}, ?S:ack_counters(S1)).

full_packet_keeps_the_ack_pending_test() ->
    S0 = ?S:state_owing_ack(1, true),
    #{ack_timer := Timer} = ?S:ack_counters(S0),
    %% A full packet carries the whole data budget (1100 without PMTU state).
    Frame = {stream, 0, 0, binary:copy(<<"x">>, 1100), false},
    S1 = send(quic_frame:encode(Frame), [Frame], S0),
    ?assertEqual([Frame], last_sent_frames(S1)),
    ?assertMatch(
        #{ack_sent := 0, ack_elicited_count := 1, ack_timer := Timer}, ?S:ack_counters(S1)
    ).

non_eliciting_packet_carries_no_ack_test() ->
    S1 = send(quic_frame:encode(padding), [padding], ?S:state_owing_ack(1, true)),
    ?assertEqual(1, ?S:state_get(S1, packets_sent)),
    ?assertMatch(#{ack_sent := 0, ack_elicited_count := 1}, ?S:ack_counters(S1)).

%% Each ACK goes out once. When it is lost and the peer's packets stop
%% eliciting new ones, only the probe can still tell the peer what
%% arrived, or it never declares its own lost packets lost.
ping_probe_carries_the_ack_test() ->
    S1 = probe(?S:state_owing_ack(0, false)),
    ?assertMatch([{ack, _, _, _}, ping], last_sent_frames(S1)).

retransmit_probe_carries_the_ack_test() ->
    {Payload, Frames} = small_stream(),
    S1 = probe(send(Payload, Frames, ?S:state_owing_ack(0, false))),
    ?assertMatch([{ack, _, _, _}, {stream, 0, 0, <<"request">>, false}], last_sent_frames(S1)).

probe(State) ->
    quic_connection:handle_pto_timeout(?S:state_set(State, pto_space, app)).
