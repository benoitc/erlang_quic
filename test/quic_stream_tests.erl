%%% -*- erlang -*-
%%%
%%% Tests for QUIC Stream Management
%%%

-module(quic_stream_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Stream Creation Tests
%%====================================================================

new_client_bidi_stream_test() ->
    Stream = quic_stream:new(0, client),
    ?assertEqual(0, quic_stream:id(Stream)),
    ?assertEqual(open, quic_stream:state(Stream)),
    ?assert(quic_stream:is_local(Stream, client)),
    ?assert(quic_stream:is_bidi(Stream)),
    ?assertEqual(client, quic_stream:initiator(Stream)),
    ?assertEqual(bidirectional, quic_stream:direction(Stream)).

new_server_bidi_stream_test() ->
    Stream = quic_stream:new(1, server),
    ?assertEqual(1, quic_stream:id(Stream)),
    ?assert(quic_stream:is_local(Stream, server)),
    ?assert(quic_stream:is_bidi(Stream)),
    ?assertEqual(server, quic_stream:initiator(Stream)).

new_client_uni_stream_test() ->
    Stream = quic_stream:new(2, client),
    ?assertEqual(2, quic_stream:id(Stream)),
    ?assert(quic_stream:is_local(Stream, client)),
    ?assertNot(quic_stream:is_bidi(Stream)),
    ?assertEqual(unidirectional, quic_stream:direction(Stream)).

new_server_uni_stream_test() ->
    Stream = quic_stream:new(3, server),
    ?assertEqual(3, quic_stream:id(Stream)),
    ?assert(quic_stream:is_local(Stream, server)),
    ?assertNot(quic_stream:is_bidi(Stream)).

remote_stream_starts_idle_test() ->
    %% Server receiving a client-initiated stream
    Stream = quic_stream:new(0, server),
    ?assertEqual(idle, quic_stream:state(Stream)),
    ?assertNot(quic_stream:is_local(Stream, server)).

%%====================================================================
%% Stream ID Pattern Tests
%%====================================================================

stream_id_patterns_test() ->
    %% Client-initiated bidirectional: 0, 4, 8, 12, ...
    ?assert(quic_stream:is_local(quic_stream:new(0, client), client)),
    ?assert(quic_stream:is_local(quic_stream:new(4, client), client)),
    ?assert(quic_stream:is_local(quic_stream:new(8, client), client)),

    %% Server-initiated bidirectional: 1, 5, 9, 13, ...
    ?assert(quic_stream:is_local(quic_stream:new(1, server), server)),
    ?assert(quic_stream:is_local(quic_stream:new(5, server), server)),

    %% Client-initiated unidirectional: 2, 6, 10, ...
    S2 = quic_stream:new(2, client),
    ?assert(quic_stream:is_local(S2, client)),
    ?assertNot(quic_stream:is_bidi(S2)),

    %% Server-initiated unidirectional: 3, 7, 11, ...
    S3 = quic_stream:new(3, server),
    ?assert(quic_stream:is_local(S3, server)),
    ?assertNot(quic_stream:is_bidi(S3)).

%%====================================================================
%% Send Tests
%%====================================================================

send_data_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send(Stream, <<"hello">>),
    ?assertEqual(5, quic_stream:bytes_to_send(S1)),

    {ok, S2} = quic_stream:send(S1, <<" world">>),
    ?assertEqual(11, quic_stream:bytes_to_send(S2)).

send_on_closed_stream_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send_fin(Stream),
    ?assertEqual({error, stream_closed}, quic_stream:send(S1, <<"data">>)).

get_send_data_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send(Stream, <<"hello world">>),

    %% Get partial data
    {Data1, Offset1, Fin1, S2} = quic_stream:get_send_data(S1, 5),
    ?assertEqual(<<"hello">>, Data1),
    ?assertEqual(0, Offset1),
    ?assertEqual(false, Fin1),
    ?assertEqual(6, quic_stream:bytes_to_send(S2)),

    %% Get remaining data
    {Data2, Offset2, Fin2, S3} = quic_stream:get_send_data(S2, 100),
    ?assertEqual(<<" world">>, Data2),
    ?assertEqual(5, Offset2),
    ?assertEqual(false, Fin2),
    ?assertEqual(0, quic_stream:bytes_to_send(S3)).

send_with_fin_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send(Stream, <<"data">>),
    {ok, S2} = quic_stream:send_fin(S1),

    {Data, _Offset, Fin, _S3} = quic_stream:get_send_data(S2, 100),
    ?assertEqual(<<"data">>, Data),
    ?assertEqual(true, Fin).

can_send_test() ->
    Stream = quic_stream:new(0, client),
    ?assert(quic_stream:can_send(Stream)),

    {ok, Closed} = quic_stream:send_fin(Stream),
    ?assertNot(quic_stream:can_send(Closed)).

%%====================================================================
%% Receive Tests
%%====================================================================

receive_in_order_test() ->
    Stream = quic_stream:new(0, server),
    {ok, S1} = quic_stream:receive_data(Stream, 0, <<"hello">>, false),
    ?assertEqual(5, quic_stream:bytes_available(S1)),

    {Data, S2} = quic_stream:read(S1),
    ?assertEqual(<<"hello">>, Data),
    ?assertEqual(0, quic_stream:bytes_available(S2)).

receive_out_of_order_test() ->
    Stream = quic_stream:new(0, server),
    %% Receive chunk at offset 5 first
    {ok, S1} = quic_stream:receive_data(Stream, 5, <<" world">>, false),
    % Not contiguous yet
    ?assertEqual(0, quic_stream:bytes_available(S1)),

    %% Now receive chunk at offset 0
    {ok, S2} = quic_stream:receive_data(S1, 0, <<"hello">>, false),
    % Now contiguous
    ?assertEqual(11, quic_stream:bytes_available(S2)),

    {Data, _S3} = quic_stream:read(S2),
    ?assertEqual(<<"hello world">>, Data).

receive_with_fin_test() ->
    Stream = quic_stream:new(0, server),
    {ok, S1} = quic_stream:receive_data(Stream, 0, <<"data">>, true),
    ?assertEqual(half_closed_remote, quic_stream:state(S1)),
    ?assert(quic_stream:is_recv_closed(S1)).

read_partial_test() ->
    Stream = quic_stream:new(0, server),
    {ok, S1} = quic_stream:receive_data(Stream, 0, <<"hello world">>, false),

    {Data1, S2} = quic_stream:read(S1, 5),
    ?assertEqual(<<"hello">>, Data1),
    ?assertEqual(6, quic_stream:bytes_available(S2)),

    {Data2, _S3} = quic_stream:read(S2, 3),
    ?assertEqual(<<" wo">>, Data2).

receive_on_closed_stream_test() ->
    Stream = quic_stream:new(0, server),
    {ok, S1} = quic_stream:receive_data(Stream, 0, <<>>, true),
    ?assertEqual(
        {error, stream_closed},
        quic_stream:receive_data(S1, 0, <<"more">>, false)
    ).

%%====================================================================
%% Flow Control Tests
%%====================================================================

update_send_window_test() ->
    Stream = quic_stream:new(0, client, #{send_max_data => 100}),
    S1 = quic_stream:update_send_window(Stream, 200),
    %% New limit should be higher
    ?assert(quic_stream:can_send(S1)).

update_send_window_no_decrease_test() ->
    Stream = quic_stream:new(0, client, #{send_max_data => 100}),
    S1 = quic_stream:update_send_window(Stream, 50),
    %% Should not decrease
    ?assert(quic_stream:can_send(S1)).

blocked_test() ->
    %% Create stream with small window
    Stream = quic_stream:new(0, client, #{send_max_data => 5}),
    ?assertNot(quic_stream:blocked(Stream)),

    %% Send data to fill window
    {ok, S1} = quic_stream:send(Stream, <<"hello world">>),
    {_Data, _Offset, _Fin, S2} = quic_stream:get_send_data(S1, 5),
    ?assert(quic_stream:blocked(S2)).

%%====================================================================
%% State Transition Tests
%%====================================================================

reset_stream_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send(Stream, <<"pending data">>),
    S2 = quic_stream:reset(S1, 1),

    ?assertEqual(closed, quic_stream:state(S2)),
    ?assertEqual(0, quic_stream:bytes_to_send(S2)).

stop_sending_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send(Stream, <<"data">>),
    S2 = quic_stream:stop_sending(S1, 2),
    ?assertEqual(0, quic_stream:bytes_to_send(S2)).

close_stream_test() ->
    Stream = quic_stream:new(0, client),
    S1 = quic_stream:close(Stream),
    ?assert(quic_stream:is_closed(S1)).

half_closed_local_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send_fin(Stream),
    ?assertEqual(half_closed_local, quic_stream:state(S1)),
    ?assert(quic_stream:is_send_closed(S1)),
    ?assertNot(quic_stream:is_recv_closed(S1)).

half_closed_remote_test() ->
    Stream = quic_stream:new(0, server),
    {ok, S1} = quic_stream:receive_data(Stream, 0, <<"data">>, true),
    ?assertEqual(half_closed_remote, quic_stream:state(S1)),
    ?assertNot(quic_stream:is_send_closed(S1)),
    ?assert(quic_stream:is_recv_closed(S1)).

full_close_sequence_test() ->
    %% Start as server receiving client stream
    Stream = quic_stream:new(0, server),

    %% Receive FIN from client
    {ok, S1} = quic_stream:receive_data(Stream, 0, <<"request">>, true),
    ?assertEqual(half_closed_remote, quic_stream:state(S1)),

    %% Send FIN back
    {ok, S2} = quic_stream:send(S1, <<"response">>),
    {ok, S3} = quic_stream:send_fin(S2),
    ?assertEqual(closed, quic_stream:state(S3)).

%%====================================================================
%% Custom Options Tests
%%====================================================================

custom_flow_control_limits_test() ->
    Opts = #{
        send_max_data => 1000,
        recv_max_data => 2000
    },
    Stream = quic_stream:new(0, client, Opts),
    ?assert(quic_stream:can_send(Stream)).

%%====================================================================
%% Edge Cases
%%====================================================================

empty_send_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send(Stream, <<>>),
    ?assertEqual(0, quic_stream:bytes_to_send(S1)).

empty_receive_test() ->
    Stream = quic_stream:new(0, server),
    {ok, S1} = quic_stream:receive_data(Stream, 0, <<>>, false),
    ?assertEqual(0, quic_stream:bytes_available(S1)).

receive_fin_only_test() ->
    Stream = quic_stream:new(0, server),
    {ok, S1} = quic_stream:receive_fin(Stream, 0),
    ?assert(quic_stream:is_recv_closed(S1)).

%%====================================================================
%% Stream Priority Tests (RFC 9218)
%%====================================================================

default_priority_test() ->
    Stream = quic_stream:new(0, client),
    ?assertEqual({3, false}, quic_stream:get_priority(Stream)).

set_priority_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:set_priority(Stream, 0, true),
    ?assertEqual({0, true}, quic_stream:get_priority(S1)).

set_priority_all_levels_test() ->
    Stream = quic_stream:new(0, client),
    %% Test all urgency levels 0-7
    lists:foreach(
        fun(Urgency) ->
            {ok, S} = quic_stream:set_priority(Stream, Urgency, false),
            ?assertEqual({Urgency, false}, quic_stream:get_priority(S))
        end,
        lists:seq(0, 7)
    ).

set_priority_incremental_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:set_priority(Stream, 3, true),
    ?assertEqual({3, true}, quic_stream:get_priority(S1)),
    {ok, S2} = quic_stream:set_priority(S1, 3, false),
    ?assertEqual({3, false}, quic_stream:get_priority(S2)).

set_priority_invalid_urgency_test() ->
    Stream = quic_stream:new(0, client),
    ?assertEqual(
        {error, invalid_urgency},
        quic_stream:set_priority(Stream, 8, false)
    ),
    ?assertEqual(
        {error, invalid_urgency},
        quic_stream:set_priority(Stream, -1, false)
    ).
