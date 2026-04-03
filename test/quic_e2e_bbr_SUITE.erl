%%% -*- erlang -*-
%%%
%%% QUIC End-to-End Test Suite with BBRv3 Congestion Control
%%%
%%% Tests the QUIC client with BBRv3 algorithm against aioquic server.
%%%
%%% Prerequisites:
%%% - Docker and docker-compose must be available
%%% - Certificates must be generated: ./certs/generate_certs.sh
%%% - Server must be running: docker compose -f docker/docker-compose.yml up -d
%%%

-module(quic_e2e_bbr_SUITE).

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

%% Test cases - Basic BBR
-export([
    bbr_basic_handshake/1,
    bbr_stream_send_receive/1,
    bbr_stream_large_data/1,
    bbr_stream_very_large_data/1,
    bbr_multiple_streams/1
]).

%% Test cases - BBR State Transitions
-export([
    bbr_startup_phase/1,
    bbr_sustained_transfer/1
]).

%% Test cases - BBR vs NewReno comparison
-export([
    compare_algorithms_small/1,
    compare_algorithms_large/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [
        {group, bbr_basic},
        {group, bbr_states},
        {group, algorithm_comparison}
    ].

groups() ->
    [
        {bbr_basic, [sequence], [
            bbr_basic_handshake,
            bbr_stream_send_receive,
            bbr_stream_large_data,
            bbr_stream_very_large_data,
            bbr_multiple_streams
        ]},
        {bbr_states, [sequence], [
            bbr_startup_phase,
            bbr_sustained_transfer
        ]},
        {algorithm_comparison, [sequence], [
            compare_algorithms_small,
            compare_algorithms_large
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),

    Host = os:getenv("QUIC_SERVER_HOST", "127.0.0.1"),
    Port = list_to_integer(os:getenv("QUIC_SERVER_PORT", "4433")),

    PrivDir = code:priv_dir(quic),
    CertsDir =
        case PrivDir of
            {error, _} ->
                filename:join([code:lib_dir(quic), "..", "certs"]);
            _ ->
                filename:join([PrivDir, "..", "certs"])
        end,
    CaCert = filename:join(CertsDir, "ca.pem"),

    ct:pal("BBR E2E Test Configuration:"),
    ct:pal("  Server: ~s:~p", [Host, Port]),
    ct:pal("  CA Cert: ~s", [CaCert]),
    ct:pal("  CC Algorithm: BBR"),

    case wait_for_server(Host, Port, 30) of
        ok ->
            ct:pal("Server is reachable"),
            [{host, Host}, {port, Port}, {ca_cert, CaCert} | Config];
        {error, Reason} ->
            ct:fail("Server not reachable: ~p", [Reason])
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting BBR test: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, _Config) ->
    ct:pal("Finished BBR test: ~p", [TestCase]),
    ok.

%%====================================================================
%% Basic BBR Tests
%%====================================================================

%% @doc Test basic QUIC handshake with BBR
bbr_basic_handshake(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>], cc_algorithm => bbr},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, Info}} ->
            ct:pal("Connected with BBR: ~p", [Info]),
            ?assert(is_map(Info)),
            quic:close(ConnRef, normal),
            ok
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test basic stream with BBR
bbr_stream_send_receive(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>], cc_algorithm => bbr},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            TestData = <<"Hello, BBR QUIC!">>,
            ok = quic:send_data(ConnRef, StreamId, TestData, true),

            receive
                {quic, ConnRef, {stream_data, StreamId, RecvData, true}} ->
                    ct:pal("BBR Received: ~p", [RecvData]),
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

%% @doc Test 100KB data transfer with BBR
bbr_stream_large_data(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>], cc_algorithm => bbr},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            DataSize = 100 * 1024,
            LargeData = crypto:strong_rand_bytes(DataSize),
            ct:pal("BBR: Sending ~p bytes", [DataSize]),

            StartTime = erlang:monotonic_time(millisecond),
            ok = quic:send_data(ConnRef, StreamId, LargeData, true),

            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 30000),
            EndTime = erlang:monotonic_time(millisecond),

            Duration = EndTime - StartTime,
            Throughput = (DataSize * 8) / (Duration / 1000) / 1000000,

            ct:pal(
                "BBR 100KB: Received ~p bytes in ~p ms (~.2f Mbps)",
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

%% @doc Test 500KB data transfer with BBR to exercise state machine
bbr_stream_very_large_data(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>], cc_algorithm => bbr},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            DataSize = 500 * 1024,
            LargeData = crypto:strong_rand_bytes(DataSize),
            ct:pal("BBR: Sending ~p bytes (500KB)", [DataSize]),

            StartTime = erlang:monotonic_time(millisecond),
            ok = quic:send_data(ConnRef, StreamId, LargeData, true),

            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 60000),
            EndTime = erlang:monotonic_time(millisecond),

            Duration = EndTime - StartTime,
            Throughput = (DataSize * 8) / (Duration / 1000) / 1000000,

            ct:pal(
                "BBR 500KB: Received ~p bytes in ~p ms (~.2f Mbps)",
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

%% @doc Test multiple concurrent streams with BBR
bbr_multiple_streams(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>], cc_algorithm => bbr},
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
%% BBR State Transition Tests
%%====================================================================

%% @doc Test BBR startup phase with burst transfer
bbr_startup_phase(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>], cc_algorithm => bbr},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            %% Send data in bursts to test startup phase
            {ok, StreamId} = quic:open_stream(ConnRef),

            %% Start with small burst
            Burst1 = crypto:strong_rand_bytes(10000),
            ok = quic:send_data(ConnRef, StreamId, Burst1, false),

            %% Wait a bit, then send larger burst
            timer:sleep(100),
            Burst2 = crypto:strong_rand_bytes(50000),
            ok = quic:send_data(ConnRef, StreamId, Burst2, false),

            %% Final burst
            timer:sleep(100),
            Burst3 = crypto:strong_rand_bytes(100000),
            ok = quic:send_data(ConnRef, StreamId, Burst3, true),

            TotalData = <<Burst1/binary, Burst2/binary, Burst3/binary>>,
            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 30000),

            ct:pal(
                "BBR Startup: Sent ~p bytes, received ~p bytes",
                [byte_size(TotalData), byte_size(ReceivedData)]
            ),

            ?assertEqual(TotalData, ReceivedData),

            quic:close(ConnRef, normal),
            ok
    after 30000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test sustained transfer to exercise ProbeBW state
bbr_sustained_transfer(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>], cc_algorithm => bbr},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            %% Send 500KB in 50KB chunks to simulate sustained transfer
            ChunkSize = 50 * 1024,
            NumChunks = 10,
            TotalSize = ChunkSize * NumChunks,

            ct:pal("BBR Sustained: Sending ~p chunks of ~p bytes", [NumChunks, ChunkSize]),

            StartTime = erlang:monotonic_time(millisecond),

            %% Send all chunks
            AllData = lists:foldl(
                fun(I, Acc) ->
                    Chunk = crypto:strong_rand_bytes(ChunkSize),
                    IsFin = (I =:= NumChunks),
                    ok = quic:send_data(ConnRef, StreamId, Chunk, IsFin),
                    <<Acc/binary, Chunk/binary>>
                end,
                <<>>,
                lists:seq(1, NumChunks)
            ),

            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 60000),
            EndTime = erlang:monotonic_time(millisecond),

            Duration = EndTime - StartTime,
            Throughput = (TotalSize * 8) / (Duration / 1000) / 1000000,

            ct:pal(
                "BBR Sustained: ~p bytes in ~p ms (~.2f Mbps)",
                [byte_size(ReceivedData), Duration, Throughput]
            ),

            ?assertEqual(TotalSize, byte_size(ReceivedData)),
            ?assertEqual(AllData, ReceivedData),

            quic:close(ConnRef, normal),
            ok
    after 60000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%%====================================================================
%% Algorithm Comparison Tests
%%====================================================================

%% @doc Compare BBR vs NewReno for small transfers
compare_algorithms_small(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    DataSize = 50 * 1024,
    TestData = crypto:strong_rand_bytes(DataSize),

    %% Test with NewReno
    NewRenoTime = transfer_with_algorithm(Host, Port, TestData, newreno),
    ct:pal("NewReno small transfer: ~p ms", [NewRenoTime]),

    %% Test with BBR
    BbrTime = transfer_with_algorithm(Host, Port, TestData, bbr),
    ct:pal("BBR small transfer: ~p ms", [BbrTime]),

    ct:pal("Comparison (50KB): NewReno=~p ms, BBR=~p ms", [NewRenoTime, BbrTime]),

    %% Both should complete successfully
    ?assert(NewRenoTime > 0),
    ?assert(BbrTime > 0),
    ok.

%% @doc Compare BBR vs NewReno for large transfers
compare_algorithms_large(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    DataSize = 500 * 1024,
    TestData = crypto:strong_rand_bytes(DataSize),

    %% Test with NewReno
    NewRenoTime = transfer_with_algorithm(Host, Port, TestData, newreno),
    NewRenoThroughput = (DataSize * 8) / (NewRenoTime / 1000) / 1000000,
    ct:pal("NewReno large transfer: ~p ms (~.2f Mbps)", [NewRenoTime, NewRenoThroughput]),

    %% Test with BBR
    BbrTime = transfer_with_algorithm(Host, Port, TestData, bbr),
    BbrThroughput = (DataSize * 8) / (BbrTime / 1000) / 1000000,
    ct:pal("BBR large transfer: ~p ms (~.2f Mbps)", [BbrTime, BbrThroughput]),

    ct:pal(
        "Comparison (500KB): NewReno=~.2f Mbps, BBR=~.2f Mbps",
        [NewRenoThroughput, BbrThroughput]
    ),

    %% Both should complete successfully
    ?assert(NewRenoTime > 0),
    ?assert(BbrTime > 0),
    ok.

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
    Opts = #{verify => false, alpn => [<<"echo">>], cc_algorithm => Algorithm},
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
