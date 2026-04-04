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
%%%

-module(quic_throughput_bench).

-export([
    run/0,
    run/1,
    compare_buffer_sizes/0,
    compare_buffer_sizes/1
]).

-include("quic.hrl").

%% Default configuration

% 5 MB
-define(DEFAULT_DATA_SIZE, 5242880).
-define(DEFAULT_PORT, 14433).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Run throughput benchmark with default settings
-spec run() -> map().
run() ->
    run(#{}).

%% @doc Run throughput benchmark with custom options
%% Options:
%%   - data_size: Total bytes to transfer (default: 5MB)
%%   - port: Server port (default: 14433)
%%   - recbuf: UDP receive buffer size (default: 7MB)
%%   - sndbuf: UDP send buffer size (default: 7MB)
-spec run(map()) -> map().
run(Opts) ->
    DataSize = maps:get(data_size, Opts, ?DEFAULT_DATA_SIZE),
    Port = maps:get(port, Opts, ?DEFAULT_PORT),
    RecvBuf = maps:get(recbuf, Opts, ?DEFAULT_UDP_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_UDP_SNDBUF),

    io:format("~n=== QUIC Throughput Benchmark ===~n"),
    io:format("Data size: ~.2f MB~n", [DataSize / 1048576]),
    io:format(
        "Requested buffers: recv=~.2f MB, send=~.2f MB~n",
        [RecvBuf / 1048576, SndBuf / 1048576]
    ),

    %% Start server
    case start_server(Port, RecvBuf, SndBuf) of
        {ok, ServerPid, ActualPort, ServerBufs} ->
            io:format(
                "Server actual buffers: recv=~p, send=~p~n",
                [maps:get(recbuf, ServerBufs), maps:get(sndbuf, ServerBufs)]
            ),

            %% Run client benchmark
            Result = run_client_benchmark(ActualPort, DataSize, RecvBuf, SndBuf),

            %% Stop server
            stop_server(ServerPid),

            Result#{
                server_buffers => ServerBufs,
                requested_recbuf => RecvBuf,
                requested_sndbuf => SndBuf
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

%%====================================================================
%% Internal Functions
%%====================================================================

start_server(Port, RecvBuf, SndBuf) ->
    %% Get test certificates
    case get_test_certs() of
        {ok, Cert, Key} ->
            ServerName = list_to_atom("throughput_bench_" ++ integer_to_list(Port)),
            ServerOpts = #{
                cert => Cert,
                key => Key,
                alpn => [<<"bench">>],
                recbuf => RecvBuf,
                sndbuf => SndBuf
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

run_client_benchmark(Port, DataSize, RecvBuf, SndBuf) ->
    ClientOpts = #{
        alpn => [<<"bench">>],
        recbuf => RecvBuf,
        sndbuf => SndBuf
    },

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

            %% Wait for acknowledgment (simplified - just measure send completion)
            timer:sleep(100),

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
