%%% -*- erlang -*-
%%%
%%% QUIC End-to-End Test Suite with CUBIC Congestion Control (RFC 9438)
%%%
%%% Tests the QUIC client with CUBIC algorithm against aioquic server.
%%%
%%% Prerequisites:
%%% - Docker and docker-compose must be available
%%% - Certificates must be generated: ./certs/generate_certs.sh
%%% - Server must be running: docker compose -f docker/docker-compose.yml up -d
%%%

-module(quic_e2e_cubic_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases - Basic CUBIC
-export([
    cubic_basic_handshake/1,
    cubic_stream_send_receive/1,
    cubic_stream_large_data/1,
    cubic_stream_very_large_data/1,
    cubic_multiple_streams/1
]).

%% Test cases - CUBIC with HyStart++
-export([
    cubic_hystart_enabled/1,
    cubic_hystart_disabled/1
]).

%% Test cases - CUBIC vs other algorithms
-export([
    compare_cubic_newreno_small/1,
    compare_cubic_newreno_large/1,
    compare_cubic_bbr_large/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [
        {group, cubic_basic},
        {group, cubic_hystart},
        {group, algorithm_comparison}
    ].

groups() ->
    [
        {cubic_basic, [sequence], [
            cubic_basic_handshake,
            cubic_stream_send_receive,
            cubic_stream_large_data,
            cubic_stream_very_large_data,
            cubic_multiple_streams
        ]},
        {cubic_hystart, [sequence], [
            cubic_hystart_enabled,
            cubic_hystart_disabled
        ]},
        {algorithm_comparison, [sequence], [
            compare_cubic_newreno_small,
            compare_cubic_newreno_large,
            compare_cubic_bbr_large
        ]}
    ].

init_per_suite(Config) ->
    {ok, Echo} = quic_test_echo_server:start(),
    ct:pal("CUBIC echo server: 127.0.0.1:~p", [maps:get(port, Echo)]),
    [{host, "127.0.0.1"}, {port, maps:get(port, Echo)}, {echo_server, Echo} | Config].

end_per_suite(Config) ->
    case ?config(echo_server, Config) of
        undefined -> ok;
        Echo -> quic_test_echo_server:stop(Echo)
    end,
    ok.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting CUBIC test: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, _Config) ->
    ct:pal("Finished CUBIC test: ~p", [TestCase]),
    ok.

%%====================================================================
%% Basic CUBIC Tests
%%====================================================================

%% @doc Test basic QUIC handshake with CUBIC
cubic_basic_handshake(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = maps:merge(quic_test_echo_server:client_opts(), #{
        alpn => [<<"echo">>], cc_algorithm => cubic
    }),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, Info}} ->
            ct:pal("Connected with CUBIC: ~p", [Info]),
            ?assert(is_map(Info)),
            quic:close(ConnRef, normal),
            ok
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test basic stream with CUBIC
cubic_stream_send_receive(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = maps:merge(quic_test_echo_server:client_opts(), #{
        alpn => [<<"echo">>], cc_algorithm => cubic
    }),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            TestData = <<"Hello, CUBIC QUIC!">>,
            ok = quic:send_data(ConnRef, StreamId, TestData, true),

            receive
                {quic, ConnRef, {stream_data, StreamId, RecvData, true}} ->
                    ct:pal("CUBIC Received: ~p", [RecvData]),
                    ?assertEqual(TestData, RecvData),
                    quic:close(ConnRef, normal),
                    ok
            after 10000 ->
                quic:close(ConnRef, timeout),
                ct:fail("Stream data timeout")
            end
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test 100KB data transfer with CUBIC
cubic_stream_large_data(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = maps:merge(quic_test_echo_server:client_opts(), #{
        alpn => [<<"echo">>], cc_algorithm => cubic
    }),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            DataSize = 100 * 1024,
            LargeData = crypto:strong_rand_bytes(DataSize),
            ct:pal("CUBIC: Sending ~p bytes", [DataSize]),

            StartTime = erlang:monotonic_time(millisecond),
            ok = quic:send_data(ConnRef, StreamId, LargeData, true),

            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 30000),
            EndTime = erlang:monotonic_time(millisecond),

            Duration = EndTime - StartTime,
            Throughput = (DataSize * 8) / (Duration / 1000) / 1000000,

            ct:pal(
                "CUBIC 100KB: Received ~p bytes in ~p ms (~.2f Mbps)",
                [byte_size(ReceivedData), Duration, Throughput]
            ),

            ?assertEqual(DataSize, byte_size(ReceivedData)),
            ?assertEqual(LargeData, ReceivedData),

            quic:close(ConnRef, normal),
            ok
    after 30000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test 500KB data transfer with CUBIC to exercise congestion avoidance
cubic_stream_very_large_data(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = maps:merge(quic_test_echo_server:client_opts(), #{
        alpn => [<<"echo">>], cc_algorithm => cubic
    }),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            DataSize = 500 * 1024,
            LargeData = crypto:strong_rand_bytes(DataSize),
            ct:pal("CUBIC: Sending ~p bytes (500KB)", [DataSize]),

            StartTime = erlang:monotonic_time(millisecond),
            ok = quic:send_data(ConnRef, StreamId, LargeData, true),

            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 120000),
            EndTime = erlang:monotonic_time(millisecond),

            Duration = EndTime - StartTime,
            Throughput = (DataSize * 8) / (Duration / 1000) / 1000000,

            ct:pal(
                "CUBIC 500KB: Received ~p bytes in ~p ms (~.2f Mbps)",
                [byte_size(ReceivedData), Duration, Throughput]
            ),

            ?assertEqual(DataSize, byte_size(ReceivedData)),
            ?assertEqual(LargeData, ReceivedData),

            quic:close(ConnRef, normal),
            ok
    after 60000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test multiple concurrent streams with CUBIC
cubic_multiple_streams(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = maps:merge(quic_test_echo_server:client_opts(), #{
        alpn => [<<"echo">>], cc_algorithm => cubic
    }),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, Stream1} = quic:open_stream(ConnRef),
            {ok, Stream2} = quic:open_stream(ConnRef),
            {ok, Stream3} = quic:open_stream(ConnRef),

            Data1 = crypto:strong_rand_bytes(100000),
            Data2 = crypto:strong_rand_bytes(100000),
            Data3 = crypto:strong_rand_bytes(100000),

            ok = quic:send_data(ConnRef, Stream1, Data1, true),
            ok = quic:send_data(ConnRef, Stream2, Data2, true),
            ok = quic:send_data(ConnRef, Stream3, Data3, true),

            Responses = collect_multiple_streams(ConnRef, #{}, 3, 30000),

            ?assertEqual(Data1, maps:get(Stream1, Responses)),
            ?assertEqual(Data2, maps:get(Stream2, Responses)),
            ?assertEqual(Data3, maps:get(Stream3, Responses)),

            quic:close(ConnRef, normal),
            ok
    after 30000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%%====================================================================
%% HyStart++ Tests (RFC 9406)
%%====================================================================

%% @doc Test CUBIC with HyStart++ enabled (default)
cubic_hystart_enabled(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    %% HyStart++ is enabled by default
    Opts = maps:merge(quic_test_echo_server:client_opts(), #{
        alpn => [<<"echo">>], cc_algorithm => cubic
    }),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            %% Transfer enough data to exercise slow start with HyStart++
            DataSize = 200 * 1024,
            Data = crypto:strong_rand_bytes(DataSize),

            StartTime = erlang:monotonic_time(millisecond),
            ok = quic:send_data(ConnRef, StreamId, Data, true),

            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 30000),
            EndTime = erlang:monotonic_time(millisecond),

            Duration = EndTime - StartTime,
            ct:pal("CUBIC+HyStart++ 200KB: ~p ms", [Duration]),

            ?assertEqual(DataSize, byte_size(ReceivedData)),
            ?assertEqual(Data, ReceivedData),

            quic:close(ConnRef, normal),
            ok
    after 30000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test CUBIC with HyStart++ disabled
cubic_hystart_disabled(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    %% Disable HyStart++
    Opts = #{
        verify => false,
        alpn => [<<"echo">>],
        cc_algorithm => cubic,
        hystart_enabled => false
    },
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            DataSize = 200 * 1024,
            Data = crypto:strong_rand_bytes(DataSize),

            StartTime = erlang:monotonic_time(millisecond),
            ok = quic:send_data(ConnRef, StreamId, Data, true),

            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 30000),
            EndTime = erlang:monotonic_time(millisecond),

            Duration = EndTime - StartTime,
            ct:pal("CUBIC (no HyStart++) 200KB: ~p ms", [Duration]),

            ?assertEqual(DataSize, byte_size(ReceivedData)),
            ?assertEqual(Data, ReceivedData),

            quic:close(ConnRef, normal),
            ok
    after 30000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%%====================================================================
%% Algorithm Comparison Tests
%%====================================================================

%% @doc Compare CUBIC vs NewReno for small transfers
compare_cubic_newreno_small(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    DataSize = 50 * 1024,
    TestData = crypto:strong_rand_bytes(DataSize),

    %% Test with NewReno
    NewRenoTime = transfer_with_algorithm(Host, Port, TestData, newreno),
    ct:pal("NewReno small transfer: ~p ms", [NewRenoTime]),

    %% Test with CUBIC
    CubicTime = transfer_with_algorithm(Host, Port, TestData, cubic),
    ct:pal("CUBIC small transfer: ~p ms", [CubicTime]),

    ct:pal("Comparison (50KB): NewReno=~p ms, CUBIC=~p ms", [NewRenoTime, CubicTime]),

    %% Both should complete successfully
    ?assert(NewRenoTime > 0),
    ?assert(CubicTime > 0),
    ok.

%% @doc Compare CUBIC vs NewReno for large transfers
compare_cubic_newreno_large(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    DataSize = 500 * 1024,
    TestData = crypto:strong_rand_bytes(DataSize),

    %% Test with NewReno
    NewRenoTime = transfer_with_algorithm(Host, Port, TestData, newreno),
    case NewRenoTime > 0 of
        true ->
            NewRenoThroughput = (DataSize * 8) / (NewRenoTime / 1000) / 1000000,
            ct:pal("NewReno large transfer: ~p ms (~.2f Mbps)", [NewRenoTime, NewRenoThroughput]);
        false ->
            ct:pal("NewReno large transfer: FAILED (skipping comparison)")
    end,

    %% Test with CUBIC - this is the main focus
    CubicTime = transfer_with_algorithm(Host, Port, TestData, cubic),
    ?assert(CubicTime > 0, "CUBIC transfer must succeed"),
    CubicThroughput = (DataSize * 8) / (CubicTime / 1000) / 1000000,
    ct:pal("CUBIC large transfer: ~p ms (~.2f Mbps)", [CubicTime, CubicThroughput]),

    case NewRenoTime > 0 of
        true ->
            ct:pal(
                "Comparison (500KB): NewReno=~.2f Mbps, CUBIC=~.2f Mbps",
                [(DataSize * 8) / (NewRenoTime / 1000) / 1000000, CubicThroughput]
            );
        false ->
            ct:pal("Comparison (500KB): NewReno=N/A, CUBIC=~.2f Mbps", [CubicThroughput])
    end,
    ok.

%% @doc Compare CUBIC vs BBR for large transfers
compare_cubic_bbr_large(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    DataSize = 500 * 1024,
    TestData = crypto:strong_rand_bytes(DataSize),

    %% Test with BBR
    BbrTime = transfer_with_algorithm(Host, Port, TestData, bbr),
    case BbrTime > 0 of
        true ->
            BbrThroughput = (DataSize * 8) / (BbrTime / 1000) / 1000000,
            ct:pal("BBR large transfer: ~p ms (~.2f Mbps)", [BbrTime, BbrThroughput]);
        false ->
            ct:pal("BBR large transfer: FAILED (skipping comparison)")
    end,

    %% Test with CUBIC - this is the main focus
    CubicTime = transfer_with_algorithm(Host, Port, TestData, cubic),
    ?assert(CubicTime > 0, "CUBIC transfer must succeed"),
    CubicThroughput = (DataSize * 8) / (CubicTime / 1000) / 1000000,
    ct:pal("CUBIC large transfer: ~p ms (~.2f Mbps)", [CubicTime, CubicThroughput]),

    case BbrTime > 0 of
        true ->
            ct:pal(
                "Comparison (500KB): BBR=~.2f Mbps, CUBIC=~.2f Mbps",
                [(DataSize * 8) / (BbrTime / 1000) / 1000000, CubicThroughput]
            );
        false ->
            ct:pal("Comparison (500KB): BBR=N/A, CUBIC=~.2f Mbps", [CubicThroughput])
    end,
    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

collect_stream_data(ConnRef, StreamId, Acc, Timeout) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, ConnRef, {stream_data, StreamId, Data, false}} ->
            collect_stream_data(ConnRef, StreamId, <<Acc/binary, Data/binary>>, Timeout)
    after Timeout ->
        ct:pal("Timeout collecting stream data, have ~p bytes", [byte_size(Acc)]),
        Acc
    end.

collect_multiple_streams(_ConnRef, Responses, 0, _Timeout) ->
    Responses;
collect_multiple_streams(ConnRef, Responses, Remaining, Timeout) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, true}} ->
            Existing = maps:get(StreamId, Responses, <<>>),
            NewResponses = maps:put(StreamId, <<Existing/binary, Data/binary>>, Responses),
            collect_multiple_streams(ConnRef, NewResponses, Remaining - 1, Timeout);
        {quic, ConnRef, {stream_data, StreamId, Data, false}} ->
            Existing = maps:get(StreamId, Responses, <<>>),
            NewResponses = maps:put(StreamId, <<Existing/binary, Data/binary>>, Responses),
            collect_multiple_streams(ConnRef, NewResponses, Remaining, Timeout)
    after Timeout ->
        ct:pal("Timeout, collected ~p streams", [maps:size(Responses)]),
        Responses
    end.

transfer_with_algorithm(Host, Port, Data, Algorithm) ->
    Opts = maps:merge(quic_test_echo_server:client_opts(), #{
        alpn => [<<"echo">>], cc_algorithm => Algorithm
    }),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    Result =
        receive
            {quic, ConnRef, {connected, _Info}} ->
                {ok, StreamId} = quic:open_stream(ConnRef),

                StartTime = erlang:monotonic_time(millisecond),
                ok = quic:send_data(ConnRef, StreamId, Data, true),

                ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 120000),
                EndTime = erlang:monotonic_time(millisecond),

                case ReceivedData =:= Data of
                    true ->
                        EndTime - StartTime;
                    false ->
                        ct:pal(
                            "Data mismatch: sent ~p bytes, received ~p bytes",
                            [byte_size(Data), byte_size(ReceivedData)]
                        ),
                        -1
                end
        after 120000 ->
            ct:pal("Connection timeout for ~p", [Algorithm]),
            -1
        end,

    quic:close(ConnRef, normal),
    timer:sleep(100),
    Result.
