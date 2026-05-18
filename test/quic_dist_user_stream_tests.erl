%%% -*- erlang -*-
%%%
%%% QUIC Distribution User Stream Unit Tests
%%% Tests basic user stream types, records, and helper functions
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_user_stream_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic_dist.hrl").

%% Helper functions to avoid "no effect" compiler warnings
test_pid() -> self().
test_ref() -> make_ref().

%%====================================================================
%% Tests
%%====================================================================

%% Test user stream thresholds. Thresholds derive from
%% ?QUIC_DIST_DATA_STREAMS, so use the same formula here.
user_stream_threshold_test_() ->
    N = ?QUIC_DIST_DATA_STREAMS,
    ExpectedClient = 4 * (N + 1),
    ExpectedServer = 4 * N + 1,
    HighestClientDist = 4 * N,
    HighestServerDist = 4 * N - 3,
    [
        {"Client threshold matches derived value", fun() ->
            ?assertEqual(ExpectedClient, ?USER_STREAM_THRESHOLD_CLIENT)
        end},
        {"Server threshold matches derived value", fun() ->
            ?assertEqual(ExpectedServer, ?USER_STREAM_THRESHOLD_SERVER)
        end},
        {"Client threshold above highest client dist stream", fun() ->
            ?assert(?USER_STREAM_THRESHOLD_CLIENT > HighestClientDist)
        end},
        {"Server threshold above highest server dist stream", fun() ->
            ?assert(?USER_STREAM_THRESHOLD_SERVER > HighestServerDist)
        end}
    ].

%% Test user stream constants
user_stream_constants_test_() ->
    [
        {"STREAM_REFUSED error code is defined", fun() ->
            ?assertEqual(16#100, ?STREAM_REFUSED)
        end},
        {"USER_STREAM_MIN_PRIORITY is 16", fun() ->
            ?assertEqual(16, ?USER_STREAM_MIN_PRIORITY)
        end},
        {"USER_STREAM_DEFAULT_PRIORITY is 128", fun() ->
            ?assertEqual(128, ?USER_STREAM_DEFAULT_PRIORITY)
        end},
        {"Min priority is less than default", fun() ->
            ?assert(?USER_STREAM_MIN_PRIORITY < ?USER_STREAM_DEFAULT_PRIORITY)
        end},
        {"Default priority is in valid range", fun() ->
            ?assert(?USER_STREAM_DEFAULT_PRIORITY >= ?USER_STREAM_MIN_PRIORITY),
            ?assert(?USER_STREAM_DEFAULT_PRIORITY =< 255)
        end}
    ].

%% Test stream_ref type construction
stream_ref_test_() ->
    [
        {"Stream ref is a tuple", fun() ->
            Ref = {quic_dist_stream, 'node@host', 20},
            ?assertMatch({quic_dist_stream, _, _}, Ref)
        end},
        {"Stream ref contains node", fun() ->
            Node = 'test@localhost',
            Ref = {quic_dist_stream, Node, 20},
            {quic_dist_stream, RefNode, _} = Ref,
            ?assertEqual(Node, RefNode)
        end},
        {"Stream ref contains stream id", fun() ->
            StreamId = 24,
            Ref = {quic_dist_stream, 'node@host', StreamId},
            {quic_dist_stream, _, RefStreamId} = Ref,
            ?assertEqual(StreamId, RefStreamId)
        end}
    ].

%% Test user_stream record
user_stream_record_test_() ->
    [
        {"Default recv_fin is false", fun() ->
            US = #user_stream{id = 20, owner = test_pid(), monitor = test_ref()},
            ?assertEqual(false, US#user_stream.recv_fin)
        end},
        {"Default send_fin is false", fun() ->
            US = #user_stream{id = 20, owner = test_pid(), monitor = test_ref()},
            ?assertEqual(false, US#user_stream.send_fin)
        end},
        {"Default priority is USER_STREAM_DEFAULT_PRIORITY", fun() ->
            US = #user_stream{id = 20, owner = test_pid(), monitor = test_ref()},
            ?assertEqual(?USER_STREAM_DEFAULT_PRIORITY, US#user_stream.priority)
        end},
        {"Can set recv_fin to true", fun() ->
            US = #user_stream{id = 20, owner = test_pid(), monitor = test_ref(), recv_fin = true},
            ?assertEqual(true, US#user_stream.recv_fin)
        end},
        {"Can set send_fin to true", fun() ->
            US = #user_stream{id = 20, owner = test_pid(), monitor = test_ref(), send_fin = true},
            ?assertEqual(true, US#user_stream.send_fin)
        end},
        {"Can set custom priority", fun() ->
            US = #user_stream{id = 20, owner = test_pid(), monitor = test_ref(), priority = 64},
            ?assertEqual(64, US#user_stream.priority)
        end},
        {"Record stores owner pid", fun() ->
            Owner = test_pid(),
            US = #user_stream{id = 20, owner = Owner, monitor = test_ref()},
            ?assertEqual(Owner, US#user_stream.owner)
        end},
        {"Record stores stream id", fun() ->
            US = #user_stream{id = 42, owner = test_pid(), monitor = test_ref()},
            ?assertEqual(42, US#user_stream.id)
        end}
    ].

%% Test message formats
message_format_test_() ->
    [
        {"Data message format", fun() ->
            StreamRef = {quic_dist_stream, 'node@host', 20},
            Data = <<"test data">>,
            Msg = {quic_dist_stream, StreamRef, {data, Data, false}},
            ?assertMatch({quic_dist_stream, {quic_dist_stream, _, _}, {data, _, false}}, Msg)
        end},
        {"Data message with FIN", fun() ->
            StreamRef = {quic_dist_stream, 'node@host', 20},
            Msg = {quic_dist_stream, StreamRef, {data, <<"last">>, true}},
            ?assertMatch({quic_dist_stream, _, {data, _, true}}, Msg)
        end},
        {"Reset message format", fun() ->
            StreamRef = {quic_dist_stream, 'node@host', 20},
            Msg = {quic_dist_stream, StreamRef, {reset, 0}},
            ?assertMatch({quic_dist_stream, _, {reset, _}}, Msg)
        end},
        {"Reset message with STREAM_REFUSED code", fun() ->
            StreamRef = {quic_dist_stream, 'node@host', 20},
            Msg = {quic_dist_stream, StreamRef, {reset, ?STREAM_REFUSED}},
            ?assertMatch({quic_dist_stream, _, {reset, 16#100}}, Msg)
        end},
        {"Closed message format", fun() ->
            StreamRef = {quic_dist_stream, 'node@host', 20},
            Msg = {quic_dist_stream, StreamRef, closed},
            ?assertMatch({quic_dist_stream, _, closed}, Msg)
        end}
    ].

%% Test stream ID classification
%% Note: is_user_stream checks based on stream ID bits, NOT connection role
%% Even IDs (bit 0 = 0): client-initiated, use CLIENT threshold
%% Odd IDs (bit 0 = 1): server-initiated, use SERVER threshold
stream_id_classification_test_() ->
    N = ?QUIC_DIST_DATA_STREAMS,
    %% First user-stream id on each side is the threshold itself.
    UserClient = ?USER_STREAM_THRESHOLD_CLIENT,
    UserServer = ?USER_STREAM_THRESHOLD_SERVER,
    HighestClientDist = 4 * N,
    HighestServerDist = 4 * N - 3,
    [
        {"Control stream (0) is client-initiated (even), not user stream", fun() ->
            % bit 0 = 0, client-initiated
            ?assertEqual(0, 0 band 1),
            ?assert(0 < ?USER_STREAM_THRESHOLD_CLIENT)
        end},
        {"Stream 1 is server-initiated (odd), not user stream", fun() ->
            % bit 0 = 1, server-initiated
            ?assertEqual(1, 1 band 1),
            ?assert(1 < ?USER_STREAM_THRESHOLD_SERVER)
        end},
        {"Client data stream 4 (even) is not user stream", fun() ->
            ?assertEqual(0, 4 band 1),
            ?assert(4 < ?USER_STREAM_THRESHOLD_CLIENT)
        end},
        {"Highest client dist stream is not user stream", fun() ->
            ?assertEqual(0, HighestClientDist band 1),
            ?assert(HighestClientDist < ?USER_STREAM_THRESHOLD_CLIENT)
        end},
        {"Highest server dist stream is not user stream", fun() ->
            ?assertEqual(1, HighestServerDist band 1),
            ?assert(HighestServerDist < ?USER_STREAM_THRESHOLD_SERVER)
        end},
        {"First client user-stream id is user stream", fun() ->
            ?assertEqual(0, UserClient band 1),
            ?assert(UserClient >= ?USER_STREAM_THRESHOLD_CLIENT)
        end},
        {"First server user-stream id is user stream", fun() ->
            ?assertEqual(1, UserServer band 1),
            ?assert(UserServer >= ?USER_STREAM_THRESHOLD_SERVER)
        end},
        {"High client id uses client threshold", fun() ->
            HighClient = UserClient + 32,
            ?assertEqual(0, HighClient band 1),
            ?assert(HighClient >= ?USER_STREAM_THRESHOLD_CLIENT)
        end},
        {"High server id uses server threshold", fun() ->
            HighServer = UserServer + 32,
            ?assertEqual(1, HighServer band 1),
            ?assert(HighServer >= ?USER_STREAM_THRESHOLD_SERVER)
        end}
    ].

%% Test is_user_stream helper function logic
%% This tests the correct implementation based on stream ID bit, not role
is_user_stream_logic_test_() ->
    IsUserStream = fun(StreamId) ->
        case StreamId band 1 of
            % Client-initiated
            0 -> StreamId >= ?USER_STREAM_THRESHOLD_CLIENT;
            % Server-initiated
            1 -> StreamId >= ?USER_STREAM_THRESHOLD_SERVER
        end
    end,
    N = ?QUIC_DIST_DATA_STREAMS,
    HighestClientDist = 4 * N,
    HighestServerDist = 4 * N - 3,
    UserClient = ?USER_STREAM_THRESHOLD_CLIENT,
    UserServer = ?USER_STREAM_THRESHOLD_SERVER,
    [
        {"Stream 0 (control, client-initiated) is not user stream", fun() ->
            ?assertNot(IsUserStream(0))
        end},
        {"Stream 1 (server-initiated) is not user stream", fun() ->
            ?assertNot(IsUserStream(1))
        end},
        {"Stream 4 (client data) is not user stream", fun() ->
            ?assertNot(IsUserStream(4))
        end},
        {"Stream 5 (server data) is not user stream", fun() ->
            ?assertNot(IsUserStream(5))
        end},
        {"Highest client dist stream is not user stream", fun() ->
            ?assertNot(IsUserStream(HighestClientDist))
        end},
        {"Highest server dist stream is not user stream", fun() ->
            ?assertNot(IsUserStream(HighestServerDist))
        end},
        {"First client user-stream id IS user stream", fun() ->
            ?assert(IsUserStream(UserClient))
        end},
        {"First server user-stream id IS user stream", fun() ->
            ?assert(IsUserStream(UserServer))
        end},
        {"Higher client id IS user stream", fun() ->
            ?assert(IsUserStream(UserClient + 4))
        end},
        {"Higher server id IS user stream", fun() ->
            ?assert(IsUserStream(UserServer + 4))
        end}
    ].
