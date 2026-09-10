%%% -*- erlang -*-
%%%
%%% ACKs are per packet-number space (RFC 9000 §12.3, RFC 9002 §A.10).
%%%
%%% Packet numbers restart at 0 in each space, so the same number means
%%% a different packet in Initial, Handshake and 1-RTT. Only 1-RTT
%%% packets are registered in the connection's loss tracker, so feeding
%%% it a Handshake-space ACK of packet numbers 0..N acknowledges the
%%% first N 1-RTT packets that were never acknowledged at all. They
%%% leave the sent queue, nothing retransmits them, and the peer is left
%%% with a permanent hole in the stream.
%%%
%%% These tests pin the isolation at the frame-dispatch boundary: an ACK
%%% arriving at a non-application encryption level must leave the loss
%%% tracker exactly as it found it, while an application-level ACK must
%%% still be processed normally.
%%%
%%% The end-to-end consequence is covered by
%%% quic_stranded_window_recovery_SUITE.

-module(quic_handshake_ack_isolation_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PACKET_BYTES, 1200).

%%====================================================================
%% Helpers
%%====================================================================

%% Three ack-eliciting 1-RTT packets in flight. The send times are real
%% monotonic milliseconds because processing an application ACK arms the
%% PTO timer, and a timestamp far in the past yields a negative delay.
loss_with_three_inflight() ->
    Now = erlang:monotonic_time(millisecond),
    S0 = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(S0, 0, ?PACKET_BYTES, true, [], Now),
    S2 = quic_loss:on_packet_sent(S1, 1, ?PACKET_BYTES, true, [], Now + 1),
    quic_loss:on_packet_sent(S2, 2, ?PACKET_BYTES, true, [], Now + 2).

%% Each call stamps the in-flight packets with the current clock, so a
%% test comparing a before and an after snapshot must build the state
%% once: two builds either side of a millisecond tick differ in
%% time_sent and nothing else.
state() ->
    quic_connection:test_state_with_loss(loss_with_three_inflight()).

%% An ACK frame in the shape process_frame/3 consumes. Each range is
%% {LargestAcked, FirstRange} where FirstRange is a *count* of further
%% packets below the largest, as on the wire (RFC 9000 §19.3), not the
%% smallest packet number.
ack(Ranges) ->
    {ack, Ranges, 0, undefined}.

%% Acknowledge all three packets, 0..2.
ack_all() ->
    ack([{2, 2}]).

%% Everything about the tracker a stray ACK could disturb.
snapshot(State) ->
    L = quic_connection:test_loss_state(State),
    #{
        in_flight => quic_loss:bytes_in_flight(L),
        sent => quic_loss:sent_packets(L),
        oldest => quic_loss:oldest_unacked(L),
        pto_count => quic_loss:pto_count(L)
    }.

%%====================================================================
%% Premise
%%====================================================================

three_packets_are_in_flight_test() ->
    #{in_flight := InFlight} = snapshot(state()),
    %% Without this the isolation assertions below would hold vacuously.
    ?assertEqual(3 * ?PACKET_BYTES, InFlight).

%%====================================================================
%% Non-application levels must not touch the tracker
%%====================================================================

handshake_ack_leaves_the_tracker_untouched_test() ->
    State = state(),
    Before = snapshot(State),
    After = snapshot(quic_connection:process_frame(handshake, ack_all(), State)),
    ?assertEqual(Before, After).

initial_ack_leaves_the_tracker_untouched_test() ->
    State = state(),
    Before = snapshot(State),
    After = snapshot(quic_connection:process_frame(initial, ack_all(), State)),
    ?assertEqual(Before, After).

handshake_ack_of_a_single_packet_leaves_it_in_flight_test() ->
    %% The narrow case: one packet number that exists in both spaces.
    After = snapshot(quic_connection:process_frame(handshake, ack([{0, 0}]), state())),
    ?assertEqual(3 * ?PACKET_BYTES, maps:get(in_flight, After)).

handshake_ack_beyond_the_tracker_is_harmless_test() ->
    %% A Handshake space that outran the 1-RTT one must not be treated as
    %% an invalid range against 1-RTT packets that were never sent.
    After = snapshot(quic_connection:process_frame(handshake, ack([{99, 90}]), state())),
    ?assertEqual(3 * ?PACKET_BYTES, maps:get(in_flight, After)).

%%====================================================================
%% Application level must still work
%%====================================================================

app_ack_is_processed_test() ->
    %% The inverse case. If this passed too, the fix would have disabled
    %% ACK processing altogether rather than scoping it.
    After = snapshot(quic_connection:process_frame(app, ack_all(), state())),
    ?assertEqual(0, maps:get(in_flight, After)),
    ?assertEqual(none, maps:get(oldest, After)).

app_ack_of_a_prefix_retires_only_that_prefix_test() ->
    After = snapshot(quic_connection:process_frame(app, ack([{1, 1}]), state())),
    %% Two of the three retire; the third is still outstanding.
    ?assertEqual(?PACKET_BYTES, maps:get(in_flight, After)),
    ?assertNotEqual(none, maps:get(oldest, After)).

%%====================================================================
%% Degenerate input (fences: these hold before and after the fix)
%%====================================================================

empty_ack_is_a_no_op_at_every_level_test() ->
    State = state(),
    Before = snapshot(State),
    [
        ?assertEqual(Before, snapshot(quic_connection:process_frame(Level, ack([]), State)))
     || Level <- [initial, handshake, app]
    ].

non_ack_frame_is_unaffected_test() ->
    %% The new clause is guarded on ACK frames; a PING at handshake level
    %% must still take its own path rather than being swallowed.
    State = state(),
    Before = snapshot(State),
    After = snapshot(quic_connection:process_frame(handshake, ping, State)),
    ?assertEqual(Before, After).
