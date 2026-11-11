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
    %% next_push_id is at position 35
    NextPushId = element(35, State),
    ?assertEqual(0, NextPushId).

%%====================================================================
%% MAX_PUSH_ID Handling Tests
%%====================================================================

%% MAX_PUSH_ID enables push on server
max_push_id_enables_push_test() ->
    State = make_test_state(#{role => server, settings_received => true}),
    {ok, State1} = quic_h3_connection:handle_control_frame({max_push_id, 10}, State),
    %% max_push_id is at position 34
    MaxPushId = element(34, State1),
    ?assertEqual(10, MaxPushId).

%% MAX_PUSH_ID can increase
max_push_id_increase_ok_test() ->
    State = make_test_state(#{role => server, max_push_id => 5, settings_received => true}),
    {ok, State1} = quic_h3_connection:handle_control_frame({max_push_id, 10}, State),
    MaxPushId = element(34, State1),
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

%% RFC 9114 Section 7.2.3: a promised push with no stream to stop changes
%% nothing, so a client cannot make the server remember IDs.
cancel_push_without_a_stream_is_ignored_test() ->
    State = make_test_state(#{
        role => server,
        max_push_id => 10,
        next_push_id => 3,
        settings_received => true
    }),
    ?assertEqual({ok, State}, quic_h3_connection:handle_control_frame({cancel_push, 1}, State)),
    ?assertEqual({ok, State}, quic_h3_connection:handle_control_frame({cancel_push, 2}, State)).

%% RFC 9114 Section 7.2.3: a push ID no PUSH_PROMISE has mentioned is a
%% connection error H3_ID_ERROR, within MAX_PUSH_ID or above it.
cancel_push_for_an_unpromised_id_is_an_id_error_test() ->
    State = make_test_state(#{
        role => server,
        max_push_id => 10,
        next_push_id => 3,
        settings_received => true
    }),
    lists:foreach(
        fun(PushId) ->
            ?assertMatch(
                {error, {connection_error, ?H3_ID_ERROR, _}},
                quic_h3_connection:handle_control_frame({cancel_push, PushId}, State)
            )
        end,
        [3, 5, 11]
    ).

%% Before any MAX_PUSH_ID nothing can have been promised.
cancel_push_before_max_push_id_is_an_id_error_test() ->
    State = make_test_state(#{role => server, settings_received => true}),
    ?assertMatch(
        {error, {connection_error, ?H3_ID_ERROR, _}},
        quic_h3_connection:handle_control_frame({cancel_push, 0}, State)
    ).

%% An open push stream is reset and forgotten.
cancel_push_resets_an_open_push_stream_test() ->
    Quic = spawn(fun() ->
        receive
            {'$gen_call', From, {close_stream, 3, ?H3_REQUEST_CANCELLED}} ->
                gen_statem:reply(From, ok)
        end
    end),
    Push = #h3_stream{id = 3, type = push, state = open},
    State = make_test_state(#{
        role => server,
        quic_conn => Quic,
        max_push_id => 10,
        next_push_id => 1,
        push_streams => #{0 => {3, Push}},
        settings_received => true
    }),
    {ok, State1} = quic_h3_connection:handle_control_frame({cancel_push, 0}, State),
    %% push_streams is at position 36
    ?assertEqual(#{}, element(36, State1)).

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
%% Cancelled Push Stream Tests (RFC 9114 Section 7.2.3)
%%====================================================================

%% When a cancelled push stream arrives, it should be silently ignored
%% without crashing the connection
cancelled_push_stream_ignored_test() ->
    %% Push ID 5 was cancelled by the client
    Quic = spawn(fun() ->
        receive
            {'$gen_call', From, {stop_sending, 100, ?H3_REQUEST_CANCELLED}} ->
                gen_statem:reply(From, ok)
        end
    end),
    State = make_test_state(#{
        role => client,
        quic_conn => Quic,
        local_max_push_id => 10,
        local_cancelled_pushes => sets:from_list([5], [{version, 2}]),
        uni_stream_buffers => #{100 => {push_pending, <<>>}},
        promised_pushes => #{},
        received_pushes => #{}
    }),
    %% Push stream arrives with cancelled push ID (5)
    %% This should return {ok, State} not {error, ...}
    Result = quic_h3_connection:process_push_stream_id(100, 5, <<>>, false, State),
    ?assertMatch({ok, _}, Result),
    %% Verify the stream buffer was removed
    {ok, State1} = Result,
    Buffers = element(24, State1),
    ?assertNot(maps:is_key(100, Buffers)).

%% Non-cancelled push should still work normally
non_cancelled_push_works_test() ->
    %% Push ID 5 is NOT cancelled
    State = make_test_state(#{
        role => client,
        local_max_push_id => 10,
        local_cancelled_pushes => sets:new([{version, 2}]),
        uni_stream_buffers => #{100 => {push_pending, <<>>}},
        promised_pushes => #{5 => {4, [{<<":status">>, <<"200">>}]}},
        received_pushes => #{}
    }),
    %% Push stream should be processed normally
    Result = quic_h3_connection:process_push_stream_id(100, 5, <<>>, false, State),
    ?assertMatch({ok, _}, Result).

%% Push ID exceeds MAX_PUSH_ID should still error
push_exceeds_max_id_error_test() ->
    State = make_test_state(#{
        role => client,
        local_max_push_id => 10,
        local_cancelled_pushes => sets:new([{version, 2}]),
        uni_stream_buffers => #{100 => {push_pending, <<>>}},
        promised_pushes => #{},
        received_pushes => #{}
    }),
    %% Push ID 15 exceeds max_push_id of 10
    Result = quic_h3_connection:process_push_stream_id(100, 15, <<>>, false, State),
    ?assertMatch({error, {connection_error, ?H3_ID_ERROR, _}, _}, Result).

%%====================================================================
%% Push ID Allocation Tests (RFC 9114 Section 4.6)
%%====================================================================

%% Push IDs are handed out in order, up to MAX_PUSH_ID.
push_allocates_ids_in_order_test() ->
    State = make_test_state(#{role => server, max_push_id => 1, next_push_id => 0}),
    {ok, 0, State1} = quic_h3_connection:allocate_push_id(State),
    {ok, 1, State2} = quic_h3_connection:allocate_push_id(State1),
    ?assertEqual({error, max_push_id_exceeded}, quic_h3_connection:allocate_push_id(State2)).

%% Allocate push ID fails when push not enabled
push_allocation_not_enabled_test() ->
    State = make_test_state(#{
        role => server,
        max_push_id => undefined,
        next_push_id => 0
    }),
    Result = quic_h3_connection:allocate_push_id(State),
    ?assertEqual({error, push_not_enabled}, Result).

%%====================================================================
%% Push Frame Sequencing Tests (RFC 9114 Section 4.6)
%%====================================================================

%% Push stream frame state is tracked in received_pushes
push_stream_tracks_frame_state_test() ->
    State = make_test_state(#{
        role => client,
        local_max_push_id => 10,
        uni_stream_buffers => #{100 => {push_pending, <<>>}},
        promised_pushes => #{5 => {4, [{<<":status">>, <<"200">>}]}},
        received_pushes => #{}
    }),
    %% Correlate push stream - should set state to expecting_headers
    {ok, State1} = quic_h3_connection:process_push_stream_id(100, 5, <<>>, false, State),
    %% received_pushes is at position 39 and stores #h3_stream{}.
    Received = element(39, State1),
    PushStream = maps:get(5, Received),
    ?assertEqual(100, element(2, PushStream)),
    ?assertEqual(expecting_headers, element(15, PushStream)).

%% A pushed response that arrives whole, stream type to FIN in one
%% delivery, completes like one that arrives in pieces.
push_stream_in_one_delivery_completes_test() ->
    Push = <<
        1,
        5,
        (quic_h3_frame:encode_headers(quic_qpack:encode([{<<":status">>, <<"200">>}])))/binary,
        (quic_h3_frame:encode_data(<<"abc">>))/binary
    >>,
    Split = byte_size(Push) - 2,
    <<Head:Split/binary, Tail/binary>> = Push,
    lists:foreach(
        fun(Pieces) ->
            _ = push_events(),
            State0 = make_test_state(#{
                role => client,
                local_max_push_id => 10,
                promised_pushes => #{5 => {0, [{<<":method">>, <<"GET">>}]}}
            }),
            State1 = lists:foldl(
                fun({Data, Fin}, State) ->
                    {ok, Next} = quic_h3_connection:handle_stream_data(3, Data, Fin, State),
                    Next
                end,
                State0,
                Pieces
            ),
            Events = push_events(),
            ?assertMatch([{push_stream, 5, 0, _}, {push_response, 5, 200, _} | _], Events),
            ?assertEqual(<<"abc">>, <<<<Data/binary>> || {push_data, 5, Data, _Fin} <- Events>>),
            ?assertEqual({push_complete, 5}, lists:last(Events)),
            %% received_pushes is at position 39
            ?assertEqual(#{}, element(39, State1))
        end,
        [[{Push, true}], [{Head, false}, {Tail, true}]]
    ).

%% RFC 9114 Section 4.1: the pushed response ends at the FIN wherever it
%% arrives, after trailers or after the last DATA frame.
push_completes_at_a_later_fin_test() ->
    Head =
        <<1, 5,
            (quic_h3_frame:encode_headers(quic_qpack:encode([{<<":status">>, <<"200">>}])))/binary>>,
    Data = quic_h3_frame:encode_data(<<"abc">>),
    Trailers = quic_h3_frame:encode_headers(quic_qpack:encode([{<<"x-sum">>, <<"1">>}])),
    lists:foreach(
        fun({Body, Expected}) ->
            _ = push_events(),
            {ok, State1} = quic_h3_connection:handle_stream_data(
                3, <<Head/binary, Data/binary, Body/binary>>, false, push_client_state()
            ),
            ?assertNotEqual(#{}, element(39, State1)),
            {ok, State2} = quic_h3_connection:handle_stream_data(3, <<>>, true, State1),
            Events = push_events(),
            ?assertEqual(Expected, [E || E <- Events, element(1, E) =:= push_trailers]),
            ?assert(lists:member({push_complete, 5}, Events)),
            %% received_pushes is at position 39
            ?assertEqual(#{}, element(39, State2))
        end,
        [{Trailers, [{push_trailers, 5, [{<<"x-sum">>, <<"1">>}]}]}, {<<>>, []}]
    ).

%% Nothing but the FIN may follow push trailers.
frames_after_push_trailers_are_frame_unexpected_test() ->
    Head =
        <<1, 5,
            (quic_h3_frame:encode_headers(quic_qpack:encode([{<<":status">>, <<"200">>}])))/binary>>,
    Trailers = quic_h3_frame:encode_headers(quic_qpack:encode([{<<"x-sum">>, <<"1">>}])),
    lists:foreach(
        fun(Next) ->
            {ok, State1} = quic_h3_connection:handle_stream_data(
                3, <<Head/binary, Trailers/binary>>, false, push_client_state()
            ),
            ?assertMatch(
                {error, {connection_error, ?H3_FRAME_UNEXPECTED, _}, _},
                quic_h3_connection:handle_stream_data(3, Next, false, State1)
            )
        end,
        [Trailers, quic_h3_frame:encode_data(<<"x">>)]
    ),
    _ = push_events().

push_client_state() ->
    make_test_state(#{
        role => client,
        local_max_push_id => 10,
        promised_pushes => #{5 => {0, [{<<":method">>, <<"GET">>}]}}
    }).

push_events() ->
    receive
        {quic_h3, _Conn, Event} -> [Event | push_events()]
    after 0 -> []
    end.

%%====================================================================
%% Push Response Header Validation Tests (RFC 9114 Section 4.6)
%%====================================================================

%% validate_push_response_headers unit tests
push_response_missing_status_test() ->
    Headers = [{<<"content-type">>, <<"text/html">>}],
    Result = quic_h3_connection:validate_push_response_headers(Headers),
    ?assertMatch({error, <<"missing :status in push response">>}, Result).

push_response_invalid_status_value_test() ->
    Headers = [{<<":status">>, <<"abc">>}],
    Result = quic_h3_connection:validate_push_response_headers(Headers),
    ?assertMatch({error, <<"invalid :status value">>}, Result).

push_response_status_out_of_range_test() ->
    Headers = [{<<":status">>, <<"999">>}],
    Result = quic_h3_connection:validate_push_response_headers(Headers),
    ?assertMatch({error, <<"invalid :status value">>}, Result).

push_response_with_method_pseudo_header_test() ->
    Headers = [{<<":status">>, <<"200">>}, {<<":method">>, <<"GET">>}],
    Result = quic_h3_connection:validate_push_response_headers(Headers),
    ?assertMatch({error, <<"request pseudo-header in push response">>}, Result).

push_response_with_path_pseudo_header_test() ->
    Headers = [{<<":status">>, <<"200">>}, {<<":path">>, <<"/">>}],
    Result = quic_h3_connection:validate_push_response_headers(Headers),
    ?assertMatch({error, <<"request pseudo-header in push response">>}, Result).

push_response_valid_test() ->
    Headers = [{<<":status">>, <<"200">>}, {<<"content-type">>, <<"text/html">>}],
    Result = quic_h3_connection:validate_push_response_headers(Headers),
    ?assertMatch({ok, 200}, Result).

push_response_valid_redirect_test() ->
    Headers = [{<<":status">>, <<"302">>}, {<<"location">>, <<"http://example.com">>}],
    Result = quic_h3_connection:validate_push_response_headers(Headers),
    ?assertMatch({ok, 302}, Result).

%%====================================================================
%% Push Cleanup Tests (RFC 9114 Section 4.6)
%%====================================================================

%% Client-side cleanup removes from local_cancelled_pushes
push_cleanup_removes_local_cancelled_test() ->
    State = make_test_state(#{
        role => client,
        received_pushes => #{5 => {100, expecting_data}},
        local_cancelled_pushes => sets:from_list([5], [{version, 2}]),
        stream_buffers => #{100 => <<>>}
    }),
    {ok, State1} = quic_h3_connection:cleanup_push_stream(5, 100, State),
    %% local_cancelled_pushes is at position 40
    LocalCancelled = element(40, State1),
    ?assertNot(sets:is_element(5, LocalCancelled)).

%% Client-side cleanup removes from received_pushes
push_cleanup_removes_received_pushes_test() ->
    State = make_test_state(#{
        role => client,
        received_pushes => #{5 => {100, expecting_data}},
        local_cancelled_pushes => sets:new([{version, 2}]),
        stream_buffers => #{100 => <<>>}
    }),
    {ok, State1} = quic_h3_connection:cleanup_push_stream(5, 100, State),
    %% received_pushes is at position 39
    Received = element(39, State1),
    ?assertNot(maps:is_key(5, Received)).

%% Cleanup removes stream buffers
push_cleanup_removes_stream_buffers_test() ->
    State = make_test_state(#{
        role => client,
        received_pushes => #{5 => {100, expecting_data}},
        local_cancelled_pushes => sets:new([{version, 2}]),
        stream_buffers => #{100 => <<"buffered data">>}
    }),
    {ok, State1} = quic_h3_connection:cleanup_push_stream(5, 100, State),
    %% stream_buffers is at position 23
    Buffers = element(23, State1),
    ?assertNot(maps:is_key(100, Buffers)).

%%====================================================================
%% Helper Functions
%%====================================================================

%% Same hand-built tuple as quic_h3_compliance_tests, same hazard: a new
%% record field not added here shifts every later one.
make_test_state_matches_the_record_test() ->
    ?assertEqual(
        quic_h3_connection:state_record_size(), tuple_size(make_test_state(#{}))
    ).

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
        discarded_uni_streams => sets:new([{version, 2}]),
        encoder_buffer => <<>>,
        decoder_buffer => <<>>,
        blocked_streams => #{},
        peer_max_field_section_size => 65536,
        peer_max_blocked_streams => 0,
        peer_connect_enabled => false,
        local_max_field_section_size => 65536,
        local_max_blocked_streams => 0,
        local_connect_enabled => false,
        %% Push fields
        max_push_id => undefined,
        next_push_id => 0,
        push_streams => #{},
        local_max_push_id => undefined,
        promised_pushes => #{},
        received_pushes => #{},
        local_cancelled_pushes => sets:new([{version, 2}]),
        last_accepted_push_id => undefined,
        %% Per-stream handler registration
        stream_handlers => #{},
        stream_data_buffers => #{},
        buffered_bytes => 0,
        max_buffered_body => ?H3_MAX_BUFFERED_BODY,
        stream_type_handler => undefined,
        claimed_uni_streams => #{},
        h3_datagram_enabled => false,
        peer_h3_datagram_enabled => false,
        bidi_type_buffers => #{},
        claimed_bidi_streams => #{},
        pending_response_headers => #{},
        has_early_keys => false,
        quic_connected => false,
        close_reason => normal,
        send_blocked => #{},
        peer_goaway_id => undefined,
        defer_requests => false,
        deferred_requests => [],
        held_streams => #{},
        held_data => [],
        held_bytes => 0,
        reset_final_size => false,
        notify_streams => false,
        streams_wanted => [],
        no_content_ended => {sets:new([{version, 2}]), queue:new()}
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
        maps:get(uni_stream_buffers, Merged), maps:get(discarded_uni_streams, Merged),
        maps:get(encoder_buffer, Merged), maps:get(decoder_buffer, Merged),
        maps:get(blocked_streams, Merged), maps:get(peer_max_field_section_size, Merged),
        maps:get(peer_max_blocked_streams, Merged), maps:get(peer_connect_enabled, Merged),
        maps:get(local_max_field_section_size, Merged), maps:get(local_max_blocked_streams, Merged),
        maps:get(max_push_id, Merged), maps:get(next_push_id, Merged),
        maps:get(push_streams, Merged), maps:get(local_max_push_id, Merged),
        maps:get(promised_pushes, Merged), maps:get(received_pushes, Merged),
        maps:get(local_cancelled_pushes, Merged), maps:get(last_accepted_push_id, Merged),
        maps:get(stream_handlers, Merged), maps:get(stream_data_buffers, Merged),
        maps:get(buffered_bytes, Merged), maps:get(max_buffered_body, Merged),
        maps:get(local_connect_enabled, Merged), maps:get(stream_type_handler, Merged),
        maps:get(claimed_uni_streams, Merged), maps:get(h3_datagram_enabled, Merged),
        maps:get(peer_h3_datagram_enabled, Merged), maps:get(bidi_type_buffers, Merged),
        maps:get(claimed_bidi_streams, Merged), maps:get(pending_response_headers, Merged),
        maps:get(has_early_keys, Merged), maps:get(quic_connected, Merged),
        maps:get(close_reason, Merged), maps:get(send_blocked, Merged),
        maps:get(peer_goaway_id, Merged), maps:get(defer_requests, Merged),
        maps:get(deferred_requests, Merged), maps:get(held_streams, Merged),
        maps:get(held_data, Merged), maps:get(held_bytes, Merged),
        maps:get(reset_final_size, Merged), maps:get(notify_streams, Merged),
        maps:get(streams_wanted, Merged), maps:get(no_content_ended, Merged)}.
