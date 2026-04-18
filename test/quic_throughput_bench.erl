%%% -*- erlang -*-
%%%
%%% QUIC Throughput Benchmarking Module
%%%
%%% Measures throughput impact of UDP buffer sizing.
%%% Research shows undersized buffers can drop goodput by 40%+.
%%%
%%% Usage:
%%%   quic_throughput_bench:run().              % Run with defaults
%%%   quic_throughput_bench:run(#{data_size => 10485760}).  % 10MB
%%%   quic_throughput_bench:compare_buffer_sizes().  % Compare different sizes
%%%   quic_throughput_bench:compare_cc().       % Compare CC algorithms
%%%

-module(quic_throughput_bench).

-export([
    run/0,
    run/1,
    run_sink/0,
    run_sink/1,
    run_download_sink/0,
    run_download_sink/1,
    compare_buffer_sizes/0,
    compare_buffer_sizes/1,
    compare_cc/0,
    compare_cc/1
]).

-include("quic.hrl").

%% Default configuration

% 5 MB
-define(DEFAULT_DATA_SIZE, 5242880).
-define(DEFAULT_PORT, 14433).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Run throughput benchmark with default settings (echo mode)
-spec run() -> map().
run() ->
    run(#{}).

%% @doc Run sink benchmark with default settings.
%% Sink mode measures raw transport throughput without echo overhead.
-spec run_sink() -> map().
run_sink() ->
    run_sink(#{}).

%% @doc Run sink benchmark with custom options.
%% Options are the same as run/1.
-spec run_sink(map()) -> map().
run_sink(Opts) ->
    run(Opts#{mode => sink}).

%% @doc Run a server-to-client download benchmark and report MB/s plus
%% the server connection's batch_flushes and packets_coalesced counters
%% so the batching behaviour is visible on the same line as throughput.
-spec run_download_sink() -> map().
run_download_sink() ->
    run_download_sink(#{}).

-spec run_download_sink(map()) -> map().
run_download_sink(Opts) ->
    application:ensure_all_started(quic),
    Size = maps:get(data_size, Opts, ?DEFAULT_DATA_SIZE),
    ServerExtra = maps:with([socket_backend, server_send_batching], Opts),
    {ok, Srv} = start_download_server(ServerExtra),
    try
        Start = erlang:monotonic_time(microsecond),
        ClientExtra = maps:with([socket_backend], Opts),
        {Received, ServerStats} = do_download(Srv, Size, ClientExtra),
        End = erlang:monotonic_time(microsecond),

        Duration = max(1, End - Start),
        MBps = (byte_size(Received) / 1048576) / (Duration / 1000000),
        Flushes = maps:get(batch_flushes, ServerStats),
        Coalesced = maps:get(packets_coalesced, ServerStats),
        AckSent = maps:get(ack_sent, ServerStats, 0),
        Retransmits = maps:get(retransmits, ServerStats, 0),
        Ratio =
            case Flushes of
                0 -> 0.0;
                _ -> Coalesced / Flushes
            end,

        io:format(
            "Download ~.2f MB: ~.2f MB/s (~p ms) flushes=~p coalesced=~p ratio=~.2f "
            "ack_sent=~p retransmits=~p~n",
            [
                byte_size(Received) / 1048576,
                MBps,
                Duration div 1000,
                Flushes,
                Coalesced,
                float(Ratio),
                AckSent,
                Retransmits
            ]
        ),

        #{
            status => ok,
            data_size => byte_size(Received),
            duration_ms => Duration div 1000,
            mb_per_sec => MBps,
            batch_flushes => Flushes,
            packets_coalesced => Coalesced,
            coalesce_ratio => Ratio,
            ack_sent => AckSent,
            retransmits => Retransmits
        }
    after
        catch quic_test_echo_server:stop(Srv)
    end.

start_download_server(Extra) ->
    DownloadHandler = fun(ConnPid, _ConnRef) ->
        Handler = spawn_link(fun() -> download_loop(ConnPid, #{}) end),
        ok = quic:set_owner_sync(ConnPid, Handler),
        {ok, Handler}
    end,
    %% Raise server-side flow-control windows so multi-MB downloads do
    %% not stall waiting for the client to advance MAX_STREAM_DATA.
    Override = maps:merge(
        #{
            connection_handler => DownloadHandler,
            max_data => 64 * 1024 * 1024,
            max_stream_data_bidi_local => 32 * 1024 * 1024,
            max_stream_data_bidi_remote => 32 * 1024 * 1024,
            max_stream_data_uni => 32 * 1024 * 1024
        },
        Extra
    ),
    quic_test_echo_server:start(Override).

download_loop(Conn, Pending) ->
    receive
        {quic, Conn, {connected, _}} ->
            download_loop(Conn, Pending);
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            Prev = maps:get(StreamId, Pending, <<>>),
            Buffer = <<Prev/binary, Data/binary>>,
            case Buffer of
                <<Size:64/big-unsigned-integer, _/binary>> when Fin ->
                    %% Strict match so a send failure crashes the
                    %% handler fast instead of bleeding into the
                    %% client's collect_download timeout. The prior
                    %% `_ =' silently dropped errors and made diagnosis
                    %% harder.
                    ok = quic:send_data(Conn, StreamId, binary:copy(<<16#42>>, Size), true),
                    download_loop(Conn, maps:remove(StreamId, Pending));
                _ when Fin ->
                    download_loop(Conn, maps:remove(StreamId, Pending));
                _ ->
                    download_loop(Conn, Pending#{StreamId => Buffer})
            end;
        {quic, Conn, {closed, _}} ->
            ok;
        {quic, Conn, _} ->
            download_loop(Conn, Pending);
        _ ->
            download_loop(Conn, Pending)
    end.

do_download(#{name := Name, port := Port}, Size, ClientExtra) ->
    %% Override echo_server's 4 MB stream window so multi-MB downloads
    %% do not stall on MAX_STREAM_DATA. Keep verify=false from the base.
    %% `ClientExtra' carries optional client-side overrides (e.g.
    %% `socket_backend') from the caller.
    ClientOpts = maps:merge(
        maps:merge(quic_test_echo_server:client_opts(), #{
            max_data => 64 * 1024 * 1024,
            max_stream_data_bidi_local => 32 * 1024 * 1024,
            max_stream_data_bidi_remote => 32 * 1024 * 1024,
            max_stream_data_uni => 32 * 1024 * 1024
        }),
        ClientExtra
    ),
    {ok, Conn} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
    try
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 ->
            throw({error, connect_timeout})
        end,

        %% Snapshot baseline server-connection stats BEFORE the download
        %% request so the returned counters describe the download only,
        %% not lifetime traffic (which folds in handshake packets).
        %% The server gen_statem can still be in idle for a few ms after
        %% the client sees {connected, _} (two-way handshake timing);
        %% poll_stats/1 retries briefly to cover that race.
        %% quic_server_batching_SUITE has identical helpers.
        ServerPid = server_connection_pid(Name),
        {ok, Before} = poll_stats(ServerPid),

        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, <<Size:64/big-unsigned-integer>>, true),
        Received = collect_download(Conn, StreamId, <<>>, 30000),

        {ok, After} = poll_stats(ServerPid),
        {Received, stats_delta(After, Before)}
    after
        quic:close(Conn)
    end.

server_connection_pid(Name) ->
    {ok, ConnPids} = quic:get_server_connections(Name),
    [Pid | _] = lists:usort(ConnPids),
    Pid.

%% Retry get_stats while the server connection is still transitioning
%% out of idle. Bounded to ~1s total.
poll_stats(Pid) ->
    poll_stats(Pid, 200).

poll_stats(_Pid, 0) ->
    {error, stats_timeout};
poll_stats(Pid, N) ->
    case quic:get_stats(Pid) of
        {ok, _} = R ->
            R;
        {error, {invalid_state, _}} ->
            timer:sleep(5),
            poll_stats(Pid, N - 1);
        {error, _} = Err ->
            Err
    end.

stats_delta(After, Before) ->
    maps:from_list(
        [
            {K, maps:get(K, After, 0) - maps:get(K, Before, 0)}
         || K <- [packets_sent, batch_flushes, packets_coalesced, ack_sent, retransmits]
        ]
    ).

collect_download(Conn, StreamId, Acc, Timeout) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect_download(Conn, StreamId, <<Acc/binary, Data/binary>>, Timeout);
        {quic, Conn, {stream_closed, StreamId, _Code}} ->
            Acc;
        {quic, Conn, {closed, _}} ->
            Acc
    after Timeout ->
        error({download_timeout, byte_size(Acc)})
    end.

%% @doc Run throughput benchmark with custom options
%% Options:
%%   - data_size: Total bytes to transfer (default: 5MB)
%%   - port: Server port (default: 14433)
%%   - recbuf: UDP receive buffer size (default: 7MB)
%%   - sndbuf: UDP send buffer size (default: 7MB)
%%   - mode: echo | sink (default: echo)
-spec run(map()) -> map().
run(Opts) ->
    DataSize = maps:get(data_size, Opts, ?DEFAULT_DATA_SIZE),
    Port = maps:get(port, Opts, ?DEFAULT_PORT),
    RecvBuf = maps:get(recbuf, Opts, ?DEFAULT_UDP_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_UDP_SNDBUF),
    Mode = maps:get(mode, Opts, echo),

    ModeStr =
        case Mode of
            echo -> "Echo";
            sink -> "Sink"
        end,
    io:format("~n=== QUIC Throughput Benchmark (~s) ===~n", [ModeStr]),
    io:format("Data size: ~.2f MB~n", [DataSize / 1048576]),
    io:format(
        "Requested buffers: recv=~.2f MB, send=~.2f MB~n",
        [RecvBuf / 1048576, SndBuf / 1048576]
    ),

    %% Start server
    case start_server(Port, RecvBuf, SndBuf, Mode) of
        {ok, ServerPid, ActualPort, ServerBufs} ->
            io:format(
                "Server actual buffers: recv=~p, send=~p~n",
                [maps:get(recbuf, ServerBufs), maps:get(sndbuf, ServerBufs)]
            ),

            %% Run client benchmark. Plumb client-relevant options
            %% (currently just `socket_backend') so callers can compare
            %% the gen_udp vs socket client paths.
            ClientExtra = maps:with([socket_backend], Opts),
            Result = run_client_benchmark(
                ActualPort, DataSize, RecvBuf, SndBuf, Mode, ClientExtra
            ),

            %% Stop server
            stop_server(ServerPid),

            Result#{
                server_buffers => ServerBufs,
                requested_recbuf => RecvBuf,
                requested_sndbuf => SndBuf,
                mode => Mode
            };
        {error, Reason} ->
            io:format("Failed to start server: ~p~n", [Reason]),
            #{status => {error, Reason}}
    end.

%% @doc Compare throughput across different buffer sizes
-spec compare_buffer_sizes() -> [map()].
compare_buffer_sizes() ->
    compare_buffer_sizes(#{}).

%% @doc Compare throughput across different buffer sizes with options
-spec compare_buffer_sizes(map()) -> [map()].
compare_buffer_sizes(Opts) ->
    DataSize = maps:get(data_size, Opts, ?DEFAULT_DATA_SIZE),

    %% Buffer sizes to test (in bytes)
    BufferSizes = [
        % Let OS decide (typically 128KB-256KB)
        {os_default, 0, 0},
        % 1MB
        {small, 1048576, 1048576},
        % 4MB
        {medium, 4194304, 4194304},
        % 7MB (recommended)
        {large, 7340032, 7340032}
    ],

    io:format("~n=== Buffer Size Comparison ===~n"),
    io:format("Data size: ~.2f MB~n~n", [DataSize / 1048576]),

    Results = lists:map(
        fun({Name, RecvBuf, SndBuf}) ->
            io:format("--- Testing: ~p ---~n", [Name]),
            RunOpts =
                case RecvBuf of
                    0 -> #{data_size => DataSize};
                    _ -> #{data_size => DataSize, recbuf => RecvBuf, sndbuf => SndBuf}
                end,
            Result = run(RunOpts),
            % Brief pause between tests
            timer:sleep(500),
            {Name, Result}
        end,
        BufferSizes
    ),

    %% Print summary
    io:format("~n=== Summary ===~n"),
    io:format(
        "~-12s | ~-10s | ~-15s | ~-15s~n",
        ["Buffer Size", "MB/s", "Duration (ms)", "Actual Recv"]
    ),
    io:format("~s~n", [lists:duplicate(60, $-)]),

    lists:foreach(
        fun({Name, Result}) ->
            case maps:get(status, Result, error) of
                ok ->
                    MBps = maps:get(mb_per_sec, Result, 0),
                    Duration = maps:get(duration_ms, Result, 0),
                    ActualRecv =
                        case maps:get(client_buffers, Result, #{}) of
                            #{recbuf := R} -> R;
                            _ -> 0
                        end,
                    io:format(
                        "~-12s | ~10.2f | ~15p | ~15p~n",
                        [Name, MBps, Duration, ActualRecv]
                    );
                _ ->
                    io:format("~-12s | ERROR~n", [Name])
            end
        end,
        Results
    ),

    Results.

%% @doc Compare throughput across different congestion control algorithms
-spec compare_cc() -> [map()].
compare_cc() ->
    compare_cc(#{}).

%% @doc Compare CC algorithms with options
-spec compare_cc(map()) -> [map()].
compare_cc(Opts) ->
    DataSize = maps:get(data_size, Opts, 10 * 1024 * 1024),

    Algorithms = [newreno, cubic, bbr],

    io:format("~n=== Congestion Control Algorithm Comparison ===~n"),
    io:format("Data size: ~.2f MB~n~n", [DataSize / 1048576]),

    Results = lists:map(
        fun(Algo) ->
            io:format("--- Testing: ~p ---~n", [Algo]),
            RunOpts = #{data_size => DataSize, cc_opts => #{algorithm => Algo}},
            Result = run_sink(RunOpts),
            timer:sleep(500),
            {Algo, Result}
        end,
        Algorithms
    ),

    io:format("~n=== Summary ===~n"),
    io:format("~-12s | ~-10s | ~-15s~n", ["Algorithm", "MB/s", "Duration (ms)"]),
    io:format("~s~n", [lists:duplicate(45, $-)]),

    lists:foreach(
        fun({Algo, Result}) ->
            case maps:get(status, Result, error) of
                ok ->
                    MBps = maps:get(mb_per_sec, Result, 0),
                    Duration = maps:get(duration_ms, Result, 0),
                    io:format("~-12s | ~10.2f | ~15p~n", [Algo, MBps, Duration]);
                _ ->
                    io:format("~-12s | ERROR~n", [Algo])
            end
        end,
        Results
    ),

    Results.

%%====================================================================
%% Internal Functions
%%====================================================================

start_server(Port, RecvBuf, SndBuf, Mode) ->
    %% Get test certificates
    case get_test_certs() of
        {ok, Cert, Key} ->
            ServerName = list_to_atom("throughput_bench_" ++ integer_to_list(Port)),
            %% Large flow control windows for benchmarking (16MB)
            FlowWindow = 16777216,
            %% Select handler based on mode
            Handler =
                case Mode of
                    echo ->
                        fun(Conn) ->
                            Pid = spawn(fun() -> echo_handler(Conn) end),
                            {ok, Pid}
                        end;
                    sink ->
                        fun(Conn) ->
                            Pid = spawn(fun() -> sink_handler(Conn) end),
                            {ok, Pid}
                        end
                end,
            ServerOpts = #{
                cert => Cert,
                key => Key,
                alpn => [<<"bench">>],
                recbuf => RecvBuf,
                sndbuf => SndBuf,
                max_data => FlowWindow,
                max_stream_data_bidi_local => FlowWindow,
                max_stream_data_bidi_remote => FlowWindow,
                max_stream_data_uni => FlowWindow,
                connection_handler => Handler
            },
            case quic:start_server(ServerName, Port, ServerOpts) of
                {ok, Pid} ->
                    {ok, ActualPort} = quic:get_server_port(ServerName),
                    %% Get actual buffer sizes from a test socket
                    ServerBufs = get_actual_buffers(RecvBuf, SndBuf),
                    {ok, {ServerName, Pid}, ActualPort, ServerBufs};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, {cert_error, Reason}}
    end.

stop_server({ServerName, _Pid}) ->
    quic:stop_server(ServerName).

run_client_benchmark(Port, DataSize, RecvBuf, SndBuf, Mode, ClientExtra) ->
    %% Large flow control windows for benchmarking (16MB)
    FlowWindow = 16777216,
    ClientOpts = maps:merge(
        #{
            alpn => [<<"bench">>],
            recbuf => RecvBuf,
            sndbuf => SndBuf,
            max_data => FlowWindow,
            max_stream_data_bidi_local => FlowWindow,
            max_stream_data_bidi_remote => FlowWindow,
            max_stream_data_uni => FlowWindow
        },
        ClientExtra
    ),

    case quic:connect("127.0.0.1", Port, ClientOpts, self()) of
        {ok, Conn} ->
            %% Wait for connection
            receive
                {quic, Conn, {connected, _Info}} -> ok
            after 5000 ->
                quic:close(Conn),
                throw({error, connect_timeout})
            end,

            %% Get actual client buffer sizes
            ClientBufs = get_actual_buffers(RecvBuf, SndBuf),

            %% Generate test data
            Data = crypto:strong_rand_bytes(DataSize),

            %% Open stream and measure transfer time
            {ok, StreamId} = quic:open_stream(Conn),

            Start = erlang:monotonic_time(millisecond),
            ok = quic:send_data(Conn, StreamId, Data, true),

            %% Wait for completion based on mode
            case Mode of
                echo ->
                    %% Wait for echoed data
                    wait_stream_close(Conn, StreamId, 30000);
                sink ->
                    %% Sink mode: wait for stream close (server closes after receiving FIN)
                    wait_stream_close_sink(Conn, StreamId, 30000)
            end,

            End = erlang:monotonic_time(millisecond),
            Duration = max(1, End - Start),

            MBps = (DataSize / 1048576) / (Duration / 1000),

            quic:close(Conn),

            io:format(
                "Result: ~.2f MB/s (~p ms for ~.2f MB)~n",
                [MBps, Duration, DataSize / 1048576]
            ),

            #{
                status => ok,
                data_size => DataSize,
                duration_ms => Duration,
                mb_per_sec => MBps,
                client_buffers => ClientBufs
            };
        {error, Reason} ->
            io:format("Failed to connect: ~p~n", [Reason]),
            #{status => {error, Reason}}
    end.

get_test_certs() ->
    PrivDir = code:priv_dir(quic),
    ProjectRoot = filename:dirname(
        filename:dirname(filename:dirname(filename:dirname(filename:dirname(PrivDir))))
    ),
    CertDir = filename:join(ProjectRoot, "certs"),
    CertFile = filename:join(CertDir, "cert.pem"),
    KeyFile = filename:join(CertDir, "priv.key"),

    case {file:read_file(CertFile), file:read_file(KeyFile)} of
        {{ok, CertPem}, {ok, KeyPem}} ->
            [{_, CertDer, _}] = public_key:pem_decode(CertPem),
            [KeyEntry] = public_key:pem_decode(KeyPem),
            KeyTerm = public_key:pem_entry_decode(KeyEntry),
            {ok, CertDer, KeyTerm};
        {{error, Reason}, _} ->
            {error, {cert_read, Reason}};
        {_, {error, Reason}} ->
            {error, {key_read, Reason}}
    end.

get_actual_buffers(RequestedRecv, RequestedSnd) ->
    %% Open a temporary socket to check actual buffer sizes
    Opts =
        case RequestedRecv of
            0 -> [binary, inet];
            _ -> [binary, inet, {recbuf, RequestedRecv}, {sndbuf, RequestedSnd}]
        end,
    case gen_udp:open(0, Opts) of
        {ok, Sock} ->
            {ok, ActualOpts} = inet:getopts(Sock, [recbuf, sndbuf]),
            gen_udp:close(Sock),
            #{
                recbuf => proplists:get_value(recbuf, ActualOpts),
                sndbuf => proplists:get_value(sndbuf, ActualOpts)
            };
        {error, _} ->
            #{recbuf => 0, sndbuf => 0}
    end.

%% Wait for stream to close or receive final data (echo mode)
wait_stream_close(Conn, StreamId, Timeout) ->
    receive
        {quic, Conn, {stream_data, StreamId, _Data, true}} ->
            ok;
        {quic, Conn, {stream_closed, StreamId}} ->
            ok;
        {quic, Conn, {stream_data, StreamId, _Data, false}} ->
            wait_stream_close(Conn, StreamId, Timeout)
    after Timeout ->
        {error, timeout}
    end.

%% Wait for stream to close (sink mode - server closes stream after receiving FIN)
wait_stream_close_sink(Conn, StreamId, Timeout) ->
    receive
        {quic, Conn, {stream_closed, StreamId}} ->
            ok;
        {quic, Conn, {stream_data, StreamId, _Data, true}} ->
            %% Server sent FIN (empty response)
            ok;
        {quic, Conn, {stream_data, StreamId, _Data, false}} ->
            %% Should not happen in sink mode, but handle gracefully
            wait_stream_close_sink(Conn, StreamId, Timeout);
        {quic, Conn, {closed, _Reason}} ->
            %% Connection closed
            ok
    after Timeout ->
        {error, timeout}
    end.

%% Echo handler for benchmark server - echoes received data back
echo_handler(Conn) ->
    receive
        {quic, Conn, {connected, _Info}} ->
            echo_handler(Conn);
        {quic, Conn, {stream_opened, _StreamId}} ->
            echo_handler(Conn);
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            %% Echo data back on the same stream
            quic:send_data(Conn, StreamId, Data, Fin),
            echo_handler(Conn);
        {quic, Conn, {closed, _Reason}} ->
            ok;
        _Other ->
            echo_handler(Conn)
    end.

%% Sink handler for benchmark server - just counts bytes without echoing
%% This measures raw transport throughput without owner-process message overhead
sink_handler(Conn) ->
    sink_handler(Conn, 0).

sink_handler(Conn, BytesRecv) ->
    receive
        {quic, Conn, {connected, _Info}} ->
            sink_handler(Conn, BytesRecv);
        {quic, Conn, {stream_opened, _StreamId}} ->
            sink_handler(Conn, BytesRecv);
        {quic, Conn, {stream_data, _StreamId, Data, false}} ->
            %% Count bytes, continue receiving
            sink_handler(Conn, BytesRecv + byte_size(Data));
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            %% Final data received, close the stream to signal completion
            TotalBytes = BytesRecv + byte_size(Data),
            %% Send empty data with FIN to signal we're done receiving
            quic:send_data(Conn, StreamId, <<>>, true),
            io:format("Sink received ~.2f MB~n", [TotalBytes / 1048576]),
            sink_handler(Conn, 0);
        {quic, Conn, {closed, _Reason}} ->
            BytesRecv;
        _Other ->
            sink_handler(Conn, BytesRecv)
    end.
