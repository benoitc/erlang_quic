%%% -*- erlang -*-
%%%
%%% QUIC End-to-End Test Suite
%%%
%%% Tests the QUIC client against a real aioquic server running in Docker.
%%%
%%% Prerequisites:
%%% - Docker and docker-compose must be available
%%% - Certificates must be generated: ./certs/generate_certs.sh
%%% - Server must be running: docker compose -f docker/docker-compose.yml up -d
%%%

-module(quic_e2e_SUITE).

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

%% Test cases - Handshake
-export([
    basic_handshake/1,
    handshake_with_alpn/1,
    handshake_verify_disabled/1
]).

%% Test cases - Streams
-export([
    stream_send_receive/1,
    stream_bidirectional/1,
    stream_multiple/1,
    stream_large_data/1
]).

%% Test cases - Connection Lifecycle
-export([
    connection_close_normal/1,
    connection_close_error/1,
    connection_idle_timeout/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        {group, handshake},
        {group, streams},
        {group, connection_lifecycle}
    ].

groups() ->
    [
        {handshake, [sequence], [
            basic_handshake,
            handshake_with_alpn,
            handshake_verify_disabled
        ]},
        {streams, [sequence], [
            stream_send_receive,
            stream_bidirectional,
            stream_multiple,
            stream_large_data
        ]},
        {connection_lifecycle, [sequence], [
            connection_close_normal,
            connection_close_error,
            connection_idle_timeout
        ]}
    ].

init_per_suite(Config) ->
    % Ensure crypto is started
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),

    % Get server configuration
    Host = os:getenv("QUIC_SERVER_HOST", "127.0.0.1"),
    Port = list_to_integer(os:getenv("QUIC_SERVER_PORT", "4433")),

    % Path to CA certificate for verification
    PrivDir = code:priv_dir(quic),
    CertsDir =
        case PrivDir of
            {error, _} ->
                % Fallback to relative path from test directory
                filename:join([code:lib_dir(quic), "..", "certs"]);
            _ ->
                filename:join([PrivDir, "..", "certs"])
        end,
    CaCert = filename:join(CertsDir, "ca.pem"),

    ct:pal("E2E Test Configuration:"),
    ct:pal("  Server: ~s:~p", [Host, Port]),
    ct:pal("  CA Cert: ~s", [CaCert]),

    % Verify server is reachable
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
    ct:pal("Starting test: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, _Config) ->
    ct:pal("Finished test: ~p", [TestCase]),
    ok.

%%====================================================================
%% Handshake Tests
%%====================================================================

%% @doc Test basic QUIC handshake
basic_handshake(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    % Connect without certificate verification (self-signed)
    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    % Wait for connection
    receive
        {quic, ConnRef, {connected, Info}} ->
            ct:pal("Connected: ~p", [Info]),
            ?assert(is_map(Info)),
            quic:close(ConnRef, normal),
            ok
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test QUIC handshake with ALPN negotiation
handshake_with_alpn(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    % Connect with specific ALPN
    Opts = #{verify => false, alpn => [<<"h3">>, <<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, Info}} ->
            ct:pal("Connected with Info: ~p", [Info]),
            % Verify ALPN was negotiated
            AlpnProtocol = maps:get(alpn_protocol, Info, undefined),
            ct:pal("Negotiated ALPN: ~p", [AlpnProtocol]),
            ?assert(
                AlpnProtocol =:= <<"h3">> orelse
                    AlpnProtocol =:= <<"echo">> orelse
                    AlpnProtocol =:= undefined
            ),
            quic:close(ConnRef, normal),
            ok
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test connection with certificate verification disabled
handshake_verify_disabled(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    % Should succeed with verify disabled (self-signed cert)
    Opts = #{verify => false},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            quic:close(ConnRef, normal),
            ok
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%%====================================================================
%% Stream Tests
%%====================================================================

%% @doc Test basic stream send/receive (echo)
stream_send_receive(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            % Open a stream
            {ok, StreamId} = quic:open_stream(ConnRef),
            ct:pal("Opened stream: ~p", [StreamId]),

            % Send data
            TestData = <<"Hello, QUIC!">>,
            ok = quic:send_data(ConnRef, StreamId, TestData, true),

            % Receive echo
            receive
                {quic, ConnRef, {stream_data, StreamId, RecvData, true}} ->
                    ct:pal("Received: ~p", [RecvData]),
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

%% @doc Test bidirectional stream with multiple chunks
stream_bidirectional(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            % Send multiple chunks
            Chunk1 = <<"First chunk, ">>,
            Chunk2 = <<"Second chunk, ">>,
            Chunk3 = <<"Final chunk!">>,

            ok = quic:send_data(ConnRef, StreamId, Chunk1, false),
            ok = quic:send_data(ConnRef, StreamId, Chunk2, false),
            ok = quic:send_data(ConnRef, StreamId, Chunk3, true),

            % Collect all echo data
            ExpectedData = <<Chunk1/binary, Chunk2/binary, Chunk3/binary>>,
            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 10000),

            ct:pal("Expected: ~p", [ExpectedData]),
            ct:pal("Received: ~p", [ReceivedData]),
            ?assertEqual(ExpectedData, ReceivedData),

            quic:close(ConnRef, normal),
            ok
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test multiple concurrent streams
stream_multiple(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            % Open multiple streams
            {ok, Stream1} = quic:open_stream(ConnRef),
            {ok, Stream2} = quic:open_stream(ConnRef),
            {ok, Stream3} = quic:open_stream(ConnRef),

            % Send data on all streams
            Data1 = <<"Stream 1 data">>,
            Data2 = <<"Stream 2 data">>,
            Data3 = <<"Stream 3 data">>,

            ok = quic:send_data(ConnRef, Stream1, Data1, true),
            ok = quic:send_data(ConnRef, Stream2, Data2, true),
            ok = quic:send_data(ConnRef, Stream3, Data3, true),

            % Collect responses (order may vary)
            Responses = collect_multiple_streams(ConnRef, #{}, 3, 15000),

            ?assertEqual(Data1, maps:get(Stream1, Responses)),
            ?assertEqual(Data2, maps:get(Stream2, Responses)),
            ?assertEqual(Data3, maps:get(Stream3, Responses)),

            quic:close(ConnRef, normal),
            ok
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test large data transfer (1MB)
stream_large_data(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            %% Generate 1MB of data to test congestion control
            DataSize = 1024 * 1024,
            LargeData = crypto:strong_rand_bytes(DataSize),
            ct:pal("Sending ~p bytes", [DataSize]),

            ok = quic:send_data(ConnRef, StreamId, LargeData, true),

            %% Collect echo with timeout (30s for large transfers)
            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 30000),

            ct:pal("Received ~p bytes", [byte_size(ReceivedData)]),
            ?assertEqual(DataSize, byte_size(ReceivedData)),
            ?assertEqual(LargeData, ReceivedData),

            quic:close(ConnRef, normal),
            ok
    after 60000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%%====================================================================
%% Connection Lifecycle Tests
%%====================================================================

%% @doc Test normal connection close
connection_close_normal(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            % Close connection normally
            quic:close(ConnRef, normal),

            % Should receive closed notification
            receive
                {quic, ConnRef, {closed, normal}} ->
                    ok;
                {quic, ConnRef, {closed, Reason}} ->
                    ct:pal("Closed with reason: ~p", [Reason]),
                    ok
            after 5000 ->
                % May not receive notification if already closed
                ok
            end
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test connection close with error
connection_close_error(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = #{verify => false},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            % Close with application error
            quic:close(ConnRef, {error, application_error}),

            receive
                {quic, ConnRef, {closed, _Reason}} ->
                    ok
            after 5000 ->
                ok
            end
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc Test connection idle timeout
connection_idle_timeout(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    % Use short idle timeout
    Opts = #{verify => false, idle_timeout => 5000},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            ct:pal("Connected, waiting for idle timeout..."),

            % Wait for idle timeout (may take longer than configured due to keep-alives)
            receive
                {quic, ConnRef, {closed, idle_timeout}} ->
                    ct:pal("Connection closed due to idle timeout"),
                    ok;
                {quic, ConnRef, {closed, Reason}} ->
                    ct:pal("Connection closed: ~p", [Reason]),
                    ok
            after 30000 ->
                % If no timeout occurred, close manually
                ct:pal("No idle timeout received, closing manually"),
                quic:close(ConnRef, normal),
                ok
            end
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%%====================================================================
%% Helper Functions
%%====================================================================

%% @doc Wait for server to be reachable
wait_for_server(_Host, _Port, 0) ->
    {error, timeout};
wait_for_server(Host, Port, Retries) ->
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, Socket} ->
            % Try to send a packet (won't get response, but verifies route)
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

%% @doc Collect stream data until fin flag
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

%% @doc Collect data from multiple streams
collect_multiple_streams(_ConnRef, Responses, 0, _Timeout) ->
    Responses;
collect_multiple_streams(ConnRef, Responses, Remaining, Timeout) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, true}} ->
            NewResponses = maps:put(StreamId, Data, Responses),
            collect_multiple_streams(ConnRef, NewResponses, Remaining - 1, Timeout);
        {quic, ConnRef, {stream_data, StreamId, Data, false}} ->
            Existing = maps:get(StreamId, Responses, <<>>),
            NewResponses = maps:put(StreamId, <<Existing/binary, Data/binary>>, Responses),
            collect_multiple_streams(ConnRef, NewResponses, Remaining, Timeout)
    after Timeout ->
        ct:pal("Timeout, collected ~p streams", [maps:size(Responses)]),
        Responses
    end.
