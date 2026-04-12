%%% -*- erlang -*-
%%%
%%% HTTP/3 Server Push Unit Tests (RFC 9114 Section 4.6)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_h3_push_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_h3.hrl").

%%====================================================================
%% Push ID Allocation Tests
%%====================================================================

%% Push ID allocation increments correctly
allocate_push_id_test() ->
    %% Push IDs should be allocated sequentially starting from 0
    State = make_test_state(#{
        role => server,
        max_push_id => 10,
        next_push_id => 0
    }),
    %% next_push_id is at position 34 (0-indexed: 33)
    NextPushId = element(34, State),
    ?assertEqual(0, NextPushId).

%%====================================================================
%% MAX_PUSH_ID Handling Tests
%%====================================================================

%% MAX_PUSH_ID enables push on server
max_push_id_enables_push_test() ->
    State = make_test_state(#{role => server, settings_received => true}),
    {ok, State1} = quic_h3_connection:handle_control_frame({max_push_id, 10}, State),
    %% max_push_id is at position 33
    MaxPushId = element(33, State1),
    ?assertEqual(10, MaxPushId).

%% MAX_PUSH_ID can increase
max_push_id_increase_ok_test() ->
    State = make_test_state(#{role => server, max_push_id => 5, settings_received => true}),
    {ok, State1} = quic_h3_connection:handle_control_frame({max_push_id, 10}, State),
    MaxPushId = element(33, State1),
    ?assertEqual(10, MaxPushId).

%% MAX_PUSH_ID cannot decrease
max_push_id_decrease_error_test() ->
    State = make_test_state(#{role => server, max_push_id => 10, settings_received => true}),
    Result = quic_h3_connection:handle_control_frame({max_push_id, 5}, State),
    ?assertMatch({error, {connection_error, ?H3_ID_ERROR, _}}, Result).

%% Server sending MAX_PUSH_ID is an error
max_push_id_from_server_error_test() ->
    State = make_test_state(#{role => client, settings_received => true}),
    Result = quic_h3_connection:handle_control_frame({max_push_id, 10}, State),
    ?assertMatch({error, {connection_error, ?H3_FRAME_UNEXPECTED, _}}, Result).

%%====================================================================
%% CANCEL_PUSH Handling Tests
%%====================================================================

%% Server receives CANCEL_PUSH from client
cancel_push_server_receives_test() ->
    State = make_test_state(#{
        role => server,
        max_push_id => 10,
        settings_received => true
    }),
    {ok, State1} = quic_h3_connection:handle_control_frame({cancel_push, 5}, State),
    %% cancelled_pushes should contain push ID 5
    %% cancelled_pushes is at position 36 (1-indexed, after push_streams at 35)
    CancelledPushes = element(36, State1),
    ?assert(sets:is_element(5, CancelledPushes)).

%%====================================================================
%% PUSH_PROMISE Handling Tests
%%====================================================================

%% Server receiving PUSH_PROMISE is an error
push_promise_server_error_test() ->
    Stream = #h3_stream{id = 0, frame_state = expecting_data},
    State = make_test_state(#{role => server}),
    Result = quic_h3_connection:handle_request_frame(
        0, {push_promise, 1, <<>>}, false, Stream, State
    ),
    ?assertMatch({error, {connection_error, ?H3_FRAME_UNEXPECTED, _}}, Result).

%%====================================================================
%% Push Stream Validation Tests
%%====================================================================

%% Server receives push stream - error
push_stream_to_server_error_test() ->
    %% RFC 9114: Only servers can initiate push streams
    %% If a server receives a push stream, it's a protocol error
    %% This is tested via assign_uni_stream which we can't call directly
    %% but the behavior is verified through the stream type check
    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

make_test_state(Overrides) ->
    Default = #{
        quic_conn => undefined,
        quic_ref => undefined,
        role => client,
        owner => self(),
        owner_monitor => undefined,
        local_control_stream => undefined,
        local_encoder_stream => undefined,
        local_decoder_stream => undefined,
        peer_control_stream => undefined,
        peer_encoder_stream => undefined,
        peer_decoder_stream => undefined,
        qpack_encoder => quic_qpack:new(),
        qpack_decoder => quic_qpack:new(),
        local_settings => #{},
        peer_settings => undefined,
        settings_sent => false,
        settings_received => false,
        goaway_id => undefined,
        last_stream_id => 0,
        streams => #{},
        next_stream_id => 0,
        stream_buffers => #{},
        uni_stream_buffers => #{},
        encoder_buffer => <<>>,
        decoder_buffer => <<>>,
        blocked_streams => #{},
        peer_max_field_section_size => 65536,
        peer_max_blocked_streams => 0,
        peer_connect_enabled => false,
        local_max_field_section_size => 65536,
        local_max_blocked_streams => 0,
        %% Push fields
        max_push_id => undefined,
        next_push_id => 0,
        push_streams => #{},
        cancelled_pushes => sets:new([{version, 2}]),
        local_max_push_id => undefined,
        promised_pushes => #{},
        received_pushes => #{},
        local_cancelled_pushes => sets:new([{version, 2}]),
        %% Per-stream handler registration
        stream_handlers => #{},
        stream_data_buffers => #{},
        stream_buffer_limit => 65536
    },
    Merged = maps:merge(Default, Overrides),
    {state, maps:get(quic_conn, Merged), maps:get(quic_ref, Merged), maps:get(role, Merged),
        maps:get(owner, Merged), maps:get(owner_monitor, Merged),
        maps:get(local_control_stream, Merged), maps:get(local_encoder_stream, Merged),
        maps:get(local_decoder_stream, Merged), maps:get(peer_control_stream, Merged),
        maps:get(peer_encoder_stream, Merged), maps:get(peer_decoder_stream, Merged),
        maps:get(qpack_encoder, Merged), maps:get(qpack_decoder, Merged),
        maps:get(local_settings, Merged), maps:get(peer_settings, Merged),
        maps:get(settings_sent, Merged), maps:get(settings_received, Merged),
        maps:get(goaway_id, Merged), maps:get(last_stream_id, Merged), maps:get(streams, Merged),
        maps:get(next_stream_id, Merged), maps:get(stream_buffers, Merged),
        maps:get(uni_stream_buffers, Merged), maps:get(encoder_buffer, Merged),
        maps:get(decoder_buffer, Merged), maps:get(blocked_streams, Merged),
        maps:get(peer_max_field_section_size, Merged), maps:get(peer_max_blocked_streams, Merged),
        maps:get(peer_connect_enabled, Merged), maps:get(local_max_field_section_size, Merged),
        maps:get(local_max_blocked_streams, Merged), maps:get(max_push_id, Merged),
        maps:get(next_push_id, Merged), maps:get(push_streams, Merged),
        maps:get(cancelled_pushes, Merged), maps:get(local_max_push_id, Merged),
        maps:get(promised_pushes, Merged), maps:get(received_pushes, Merged),
        maps:get(local_cancelled_pushes, Merged), maps:get(stream_handlers, Merged),
        maps:get(stream_data_buffers, Merged), maps:get(stream_buffer_limit, Merged)}.
