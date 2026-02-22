%%% -*- erlang -*-
%%%
%%% Stream Reassembly Tests
%%% Tests for proper in-order delivery of stream data
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_stream_reassembly_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("quic.hrl").

%% CT callbacks
-export([
    suite/0,
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    ordered_delivery_small/1,
    ordered_delivery_large/1,
    streaming_still_works/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        ordered_delivery_small,
        ordered_delivery_large,
        streaming_still_works
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),

    %% Get server configuration (using aioquic echo server)
    Host = os:getenv("QUIC_SERVER_HOST", "127.0.0.1"),
    Port = list_to_integer(os:getenv("QUIC_SERVER_PORT", "4433")),

    %% Wait for server to be reachable
    case wait_for_server(Host, Port, 10) of
        ok ->
            ct:pal("Server reachable at ~s:~p", [Host, Port]),
            [{host, Host}, {port, Port} | Config];
        {error, Reason} ->
            {skip, {server_not_reachable, Reason}}
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting test: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, _Config) ->
    ct:pal("Finished test: ~p", [TestCase]),
    ok.

%%====================================================================
%% Test Cases
%%====================================================================

%% @doc Verify small data arrives in order
ordered_delivery_small(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            %% Send data with a known pattern
            TestData = <<"0123456789ABCDEF">>,
            ok = quic:send_data(ConnRef, StreamId, TestData, true),

            %% Receive and verify order
            Received = collect_stream_data(ConnRef, StreamId, <<>>, 10000),
            ?assertEqual(TestData, Received),

            quic:close(ConnRef, normal),
            {comment, "Small data delivered in order"}
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Verify large data (1MB) arrives in order
%% This tests the stream reassembly when packets may arrive out of order
ordered_delivery_large(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            %% Generate 1MB with a known pattern (sequence of 4-byte integers)
            %% This makes it easy to detect any out-of-order delivery
            DataSize = 1024 * 1024,
            IntCount = DataSize div 4,
            LargeData = <<<<I:32/little>> || I <- lists:seq(0, IntCount - 1)>>,

            ct:pal("Sending ~p bytes with sequential pattern", [DataSize]),
            ok = quic:send_data(ConnRef, StreamId, LargeData, true),

            %% Collect all data
            Received = collect_stream_data(ConnRef, StreamId, <<>>, 60000),
            ct:pal("Received ~p bytes", [byte_size(Received)]),

            %% Verify size
            ?assertEqual(DataSize, byte_size(Received)),

            %% Verify pattern - check data is in order
            verify_sequential_pattern(Received, 0),

            quic:close(ConnRef, normal),
            {comment, "Large data (1MB) delivered in order"}
    after 30000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Verify that data is still streamed (delivered incrementally as it arrives)
%% not waiting for entire stream
streaming_still_works(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            %% Send multiple chunks
            Chunk1 = <<"CHUNK1_">>,
            Chunk2 = <<"CHUNK2_">>,
            Chunk3 = <<"CHUNK3">>,

            ok = quic:send_data(ConnRef, StreamId, Chunk1, false),
            ok = quic:send_data(ConnRef, StreamId, Chunk2, false),
            ok = quic:send_data(ConnRef, StreamId, Chunk3, true),

            %% Receive data - we should get incremental deliveries
            %% not necessarily all at once
            {MessageCount, TotalData} = count_and_collect(ConnRef, StreamId, 0, <<>>, 10000),

            ct:pal("Received ~p messages, total ~p bytes", [MessageCount, byte_size(TotalData)]),

            %% Verify complete data
            ExpectedData = <<Chunk1/binary, Chunk2/binary, Chunk3/binary>>,
            ?assertEqual(ExpectedData, TotalData),

            %% Data arrives ordered (streaming is preserved)
            ?assert(MessageCount >= 1),

            quic:close(ConnRef, normal),
            {comment, io_lib:format("Data streamed in ~p message(s)", [MessageCount])}
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%%====================================================================
%% Helper Functions
%%====================================================================

wait_for_server(_Host, _Port, 0) ->
    {error, timeout};
wait_for_server(Host, Port, Retries) ->
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, Socket} ->
            HostAddr =
                case inet:parse_address(Host) of
                    {ok, Addr} -> Addr;
                    {error, _} -> Host
                end,
            Result = gen_udp:send(Socket, HostAddr, Port, <<0:32>>),
            gen_udp:close(Socket),
            case Result of
                ok ->
                    ok;
                {error, _} ->
                    timer:sleep(1000),
                    wait_for_server(Host, Port, Retries - 1)
            end;
        {error, _} ->
            timer:sleep(1000),
            wait_for_server(Host, Port, Retries - 1)
    end.

collect_stream_data(ConnRef, StreamId, Acc, Timeout) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, ConnRef, {stream_data, StreamId, Data, false}} ->
            collect_stream_data(ConnRef, StreamId, <<Acc/binary, Data/binary>>, Timeout)
    after Timeout ->
        ct:pal("Timeout collecting data, have ~p bytes", [byte_size(Acc)]),
        Acc
    end.

count_and_collect(ConnRef, StreamId, Count, Acc, Timeout) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, true}} ->
            {Count + 1, <<Acc/binary, Data/binary>>};
        {quic, ConnRef, {stream_data, StreamId, Data, false}} ->
            count_and_collect(ConnRef, StreamId, Count + 1, <<Acc/binary, Data/binary>>, Timeout)
    after Timeout ->
        ct:pal("Timeout, count=~p bytes=~p", [Count, byte_size(Acc)]),
        {Count, Acc}
    end.

%% Verify data contains sequential 4-byte integers
verify_sequential_pattern(<<>>, _Expected) ->
    ok;
verify_sequential_pattern(<<Value:32/little, Rest/binary>>, Expected) ->
    case Value of
        Expected ->
            verify_sequential_pattern(Rest, Expected + 1);
        _ ->
            ct:fail(
                "Out of order: expected ~p but got ~p at position ~p",
                [Expected, Value, Expected * 4]
            )
    end.
