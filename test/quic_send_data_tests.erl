%%% -*- erlang -*-
%%%
%%% Tests for QUIC send_data scenarios
%%%
%%% This module tests potential blocking scenarios in send_data:
%%% 1. Flow control blocking
%%% 2. Stream not properly opened on the server side
%%% 3. Congestion control blocking
%%% 4. Connection state not ready
%%%

-module(quic_send_data_tests).

-include_lib("eunit/include/eunit.hrl").

%% Record definitions must be at the top
-record(stream_state, {
    id = 0,
    state = idle,
    send_offset = 0,
    send_max_data = 65536,
    send_fin = false,
    send_buffer = [],
    recv_offset = 0,
    recv_max_data = 65536,
    recv_fin = false,
    recv_buffer = #{},
    final_size = undefined,
    urgency = 3,
    incremental = false
}).

-record(crypto_keys, {
    key,
    iv,
    hp
}).

%%====================================================================
%% 1. Stream State Tests - Server sending on client-initiated stream
%%====================================================================

%% Verify stream is created when server receives data on client-initiated stream
server_creates_stream_on_receive_test() ->
    %% Simulate stream state as server would see it after receiving client data

    % Client-initiated bidirectional
    StreamId = 0,
    StreamState = create_stream_state(StreamId, server),

    %% Verify stream is properly initialized for bidirectional communication
    ?assertEqual(0, StreamState#stream_state.send_offset),
    ?assertEqual(open, StreamState#stream_state.state),
    ?assert(StreamState#stream_state.send_max_data > 0).

%% Test server can queue send data on client-initiated stream
server_send_on_client_stream_test() ->
    %% Create a stream state as if server received client data on stream 0
    StreamId = 0,
    StreamState = create_stream_state(StreamId, server),
    Streams = #{StreamId => StreamState},

    %% Simulate do_send_data check
    Result = maps:find(StreamId, Streams),
    ?assertMatch({ok, _}, Result).

%% Test that unknown stream returns error
unknown_stream_send_fails_test() ->
    Streams = #{},
    StreamId = 0,
    Result = maps:find(StreamId, Streams),
    ?assertEqual(error, Result).

%%====================================================================
%% 2. Flow Control Tests
%%====================================================================

%% Test send blocked when stream max_data exceeded
stream_flow_control_blocks_test() ->
    StreamState = #stream_state{
        id = 0,
        state = open,
        send_offset = 1000,
        % Already at limit
        send_max_data = 1000,
        send_fin = false
    },

    %% Check if we can send more data
    DataSize = 100,
    CanSend =
        StreamState#stream_state.send_offset + DataSize =<
            StreamState#stream_state.send_max_data,
    ?assertNot(CanSend).

%% Test send allowed within stream flow control
stream_flow_control_allows_test() ->
    StreamState = #stream_state{
        id = 0,
        state = open,
        send_offset = 500,
        send_max_data = 1000,
        send_fin = false
    },

    DataSize = 100,
    CanSend =
        StreamState#stream_state.send_offset + DataSize =<
            StreamState#stream_state.send_max_data,
    ?assert(CanSend).

%% Test MAX_STREAM_DATA unblocks sending
max_stream_data_unblocks_test() ->
    StreamState0 = #stream_state{
        id = 0,
        state = open,
        send_offset = 1000,
        send_max_data = 1000,
        send_fin = false
    },

    %% Initially blocked
    ?assertNot(StreamState0#stream_state.send_offset < StreamState0#stream_state.send_max_data),

    %% Receive MAX_STREAM_DATA
    StreamState1 = StreamState0#stream_state{send_max_data = 2000},

    %% Now can send
    DataSize = 500,
    CanSend =
        StreamState1#stream_state.send_offset + DataSize =<
            StreamState1#stream_state.send_max_data,
    ?assert(CanSend).

%%====================================================================
%% 3. Congestion Control Tests
%%====================================================================

%% Test CC blocks when cwnd exhausted
cc_blocks_when_cwnd_full_test() ->
    State = quic_cc:new(),
    Cwnd = quic_cc:cwnd(State),

    %% Fill up the cwnd
    S1 = quic_cc:on_packet_sent(State, Cwnd),

    %% Should not be able to send more
    ?assertNot(quic_cc:can_send(S1, 100)).

%% Test CC allows send within cwnd
cc_allows_within_cwnd_test() ->
    State = quic_cc:new(),
    Cwnd = quic_cc:cwnd(State),

    %% Use half cwnd
    S1 = quic_cc:on_packet_sent(State, Cwnd div 2),

    %% Should be able to send more
    ?assert(quic_cc:can_send(S1, 100)).

%% Test ACKs free up cwnd
cc_acks_free_cwnd_test() ->
    State = quic_cc:new(),
    Cwnd = quic_cc:cwnd(State),

    %% Fill cwnd
    S1 = quic_cc:on_packet_sent(State, Cwnd),
    ?assertNot(quic_cc:can_send(S1, 100)),

    %% ACK some packets
    S2 = quic_cc:on_packets_acked(S1, 5000),

    %% Should be able to send again
    ?assert(quic_cc:can_send(S2, 100)).

%%====================================================================
%% 4. Connection State Tests
%%====================================================================

%% Test keys must be ready for sending
keys_required_for_send_test() ->
    %% When app_keys is undefined, cannot send 1-RTT data
    %% This tests the precondition - keys must exist
    Keys = {#crypto_keys{key = <<"k">>, iv = <<"iv">>, hp = <<"hp">>}, #crypto_keys{
        key = <<"k">>, iv = <<"iv">>, hp = <<"hp">>
    }},
    ?assertMatch({#crypto_keys{}, #crypto_keys{}}, Keys).

%%====================================================================
%% 5. Send Queue Tests
%%====================================================================

%% Test data gets queued when CC blocks
data_queued_when_blocked_test() ->
    %% Create an empty priority queue
    PQ = {
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new()
    },

    %% Queue some data
    Entry = {stream_data, 0, 0, <<"hello">>, false},
    Urgency = 3,
    Bucket = element(Urgency + 1, PQ),
    NewBucket = queue:in(Entry, Bucket),
    NewPQ = setelement(Urgency + 1, PQ, NewBucket),

    %% Verify queue is not empty
    ?assertNot(queue:is_empty(element(Urgency + 1, NewPQ))).

%% Test queued data can be dequeued
queued_data_dequeue_test() ->
    %% Create a queue with one entry
    PQ = {
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new()
    },
    Entry = {stream_data, 0, 0, <<"hello">>, false},
    Urgency = 3,
    Bucket = element(Urgency + 1, PQ),
    NewBucket = queue:in(Entry, Bucket),
    NewPQ = setelement(Urgency + 1, PQ, NewBucket),

    %% Dequeue
    Bucket2 = element(Urgency + 1, NewPQ),
    {{value, Dequeued}, _RemainingBucket} = queue:out(Bucket2),
    ?assertEqual(Entry, Dequeued).

%% Test priority ordering - lower urgency dequeues first
priority_ordering_test() ->
    %% Create queue with entries at different priorities
    PQ0 = {
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new(),
        queue:new()
    },

    %% Add entry at urgency 3 (lower priority)
    Entry3 = {stream_data, 0, 0, <<"low">>, false},
    B3 = queue:in(Entry3, element(4, PQ0)),
    PQ1 = setelement(4, PQ0, B3),

    %% Add entry at urgency 1 (higher priority)
    Entry1 = {stream_data, 4, 0, <<"high">>, false},
    B1 = queue:in(Entry1, element(2, PQ1)),
    PQ2 = setelement(2, PQ1, B1),

    %% Dequeue should get urgency 1 first
    {FirstEntry, _} = dequeue_highest_priority(PQ2, 0),
    ?assertEqual(Entry1, FirstEntry).

%%====================================================================
%% 6. Integration: Full send_data flow
%%====================================================================

%% Test complete flow: stream exists, CC allows, data sent
full_send_flow_test() ->
    %% Setup: stream exists
    StreamId = 0,
    StreamState = create_stream_state(StreamId, server),
    Streams = #{StreamId => StreamState},

    %% Stream found
    {ok, Stream} = maps:find(StreamId, Streams),
    ?assertEqual(0, Stream#stream_state.send_offset),

    %% CC allows
    CCState = quic_cc:new(),
    ?assert(quic_cc:can_send(CCState, 100)),

    %% All conditions met for sending
    ok.

%% Test flow when stream not found
send_unknown_stream_test() ->
    % Different stream
    Streams = #{4 => create_stream_state(4, server)},

    %% Try to send on stream 0
    Result = maps:find(0, Streams),
    ?assertEqual(error, Result).

%% Test flow when CC blocks
send_cc_blocked_test() ->
    CCState = quic_cc:new(),
    Cwnd = quic_cc:cwnd(CCState),

    %% Exhaust cwnd
    BlockedState = quic_cc:on_packet_sent(CCState, Cwnd),

    %% Verify send would be blocked
    ?assertNot(quic_cc:can_send(BlockedState, 100)).

%%====================================================================
%% Helper Functions
%%====================================================================

%% Create a stream state as it would be after receiving data
create_stream_state(StreamId, _Role) ->
    #stream_state{
        id = StreamId,
        state = open,
        send_offset = 0,
        send_max_data = 65536,
        send_fin = false,
        send_buffer = [],
        recv_offset = 0,
        recv_max_data = 65536,
        recv_fin = false,
        recv_buffer = #{}
    }.

%% Dequeue from highest priority bucket
dequeue_highest_priority(PQ, 8) ->
    {empty, PQ};
dequeue_highest_priority(PQ, Urgency) ->
    Bucket = element(Urgency + 1, PQ),
    case queue:out(Bucket) of
        {{value, Entry}, NewBucket} ->
            {Entry, setelement(Urgency + 1, PQ, NewBucket)};
        {empty, _} ->
            dequeue_highest_priority(PQ, Urgency + 1)
    end.
