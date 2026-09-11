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
    stream_large_data/1,
    stream_large_data_chacha/1,
    stream_many_writes_stay_in_order/1
]).

%% Test cases - Connection Lifecycle
-export([
    connection_close_normal/1,
    connection_close_error/1,
    connection_idle_timeout/1,
    keep_alive_prevents_idle_close/1
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
            stream_large_data,
            stream_large_data_chacha,
            stream_many_writes_stay_in_order
        ]},
        {connection_lifecycle, [sequence], [
            connection_close_normal,
            connection_close_error,
            connection_idle_timeout,
            keep_alive_prevents_idle_close
        ]}
    ].

init_per_suite(Config) ->
    %% Spin an in-process echo server on an ephemeral port. Matches
    %% the behaviour of docker/server/quic_server.py so these tests
    %% used to require `docker compose up'; the helper removes that
    %% dependency entirely.
    {ok, Echo} = quic_test_echo_server:start(),
    ct:pal("E2E echo server: 127.0.0.1:~p", [maps:get(port, Echo)]),
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

    Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
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

%% @doc The 1 MB echo again with ChaCha20-Poly1305 negotiated, so the
%% ChaCha header-protection and AEAD paths (fused in the NIF when it is
%% loaded, per packet otherwise) carry a real bulk transfer both ways.
stream_large_data_chacha(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    Opts = maps:merge(quic_test_echo_server:client_opts(), #{
        alpn => [<<"echo">>],
        ciphers => [chacha20_poly1305]
    }),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),
            DataSize = 1024 * 1024,
            LargeData = crypto:strong_rand_bytes(DataSize),
            ok = quic:send_data(ConnRef, StreamId, LargeData, true),
            ReceivedData = collect_stream_data(ConnRef, StreamId, <<>>, 30000),
            ?assertEqual(DataSize, byte_size(ReceivedData)),
            ?assertEqual(LargeData, ReceivedData),
            quic:close(ConnRef, normal),
            ok
    after 60000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

%% @doc A stream written in many calls must still go out in offset order.
%%
%% Asserts the mechanism rather than a stopwatch: on a lossless loopback
%% path an in-order stream never buffers anything at the receiver, so the
%% server connection's reassembly buffer stays empty for the whole
%% transfer. When the drain requeued a remainder behind the entries it was
%% ahead of, the stream interleaved permanently and this buffer grew to
%% hold almost the entire transfer.
stream_many_writes_stay_in_order(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),
    #{name := ServerName} = ?config(echo_server, Config),

    Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, StreamId} = quic:open_stream(ConnRef),

            Writes = 16,
            ChunkSize = 128 * 1024,
            Data = crypto:strong_rand_bytes(Writes * ChunkSize),

            Poller = spawn_link(fun() -> poll_recv_buffer(ServerName, self(), 0) end),
            ok = send_in_chunks(ConnRef, StreamId, Data, ChunkSize),
            Echoed = collect_stream_data(ConnRef, StreamId, <<>>, 60000),
            Poller ! {stop, self()},
            MaxBuffered =
                receive
                    {max_buffered, N} -> N
                after 5000 -> ct:fail("poller did not report")
                end,

            ct:pal("~p writes, peak server reassembly buffer ~p bytes", [Writes, MaxBuffered]),
            ?assertEqual(byte_size(Data), byte_size(Echoed)),
            ?assertEqual(Data, Echoed),
            %% A stray reordered packet would be a couple of kB; the bug
            %% buffered megabytes.
            ?assert(MaxBuffered < 128 * 1024),

            quic:close(ConnRef, normal),
            ok
    after 60000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
    end.

send_in_chunks(Conn, StreamId, Data, ChunkSize) when byte_size(Data) =< ChunkSize ->
    quic:send_data(Conn, StreamId, Data, true);
send_in_chunks(Conn, StreamId, Data, ChunkSize) ->
    <<Head:ChunkSize/binary, Rest/binary>> = Data,
    ok = quic:send_data(Conn, StreamId, Head, false),
    send_in_chunks(Conn, StreamId, Rest, ChunkSize).

poll_recv_buffer(ServerName, Parent, Max) ->
    receive
        {stop, From} -> From ! {max_buffered, Max}
    after 2 ->
        poll_recv_buffer(ServerName, Parent, max(Max, server_recv_buffered(ServerName)))
    end.

server_recv_buffered(ServerName) ->
    case quic:get_server_connections(ServerName) of
        {ok, [Conn | _]} ->
            try quic_connection:get_state(Conn) of
                {_StateName, #{recv_buffer_bytes := Bytes}} -> Bytes;
                _ -> 0
            catch
                _:_ -> 0
            end;
        _ ->
            0
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

%% @doc Keep-alive must keep an otherwise-idle connection open past its
%% idle timeout. The keep-alive timer is armed at the connected transition
%% (not at init) and re-arms on each fire, so PINGs sent every
%% keep_alive_interval reset activity and the idle timer never elapses.
%% A regression that armed keep-alive too early (and lost it during a long
%% handshake) or failed to re-arm would let the idle timeout close the
%% connection here.
keep_alive_prevents_idle_close(Config) ->
    Host = ?config(host, Config),
    Port = ?config(port, Config),

    %% keep_alive (5s, the minimum) fires before the 8s idle timeout, so the
    %% connection should stay open well past 8s of application inactivity.
    Opts = #{verify => false, idle_timeout => 8000, keep_alive_interval => 5000},
    {ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

    receive
        {quic, ConnRef, {connected, _Info}} ->
            receive
                {quic, ConnRef, {closed, idle_timeout}} ->
                    ct:fail("Connection idle-closed despite keep-alive");
                {quic, ConnRef, {closed, Reason}} ->
                    ct:fail({unexpected_close, Reason})
            after 14000 ->
                %% Survived >1.5 idle windows: keep-alive is working.
                quic:close(ConnRef, normal),
                ok
            end
    after 10000 ->
        quic:close(ConnRef, timeout),
        ct:fail("Connection timeout")
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
