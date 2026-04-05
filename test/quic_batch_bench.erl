%%% -*- erlang -*-
%%%
%%% UDP Packet Batching Benchmark
%%% Cross-platform benchmark comparing batched vs non-batched throughput
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_batch_bench).

-export([
    run/0,
    run/1,
    quick/0
]).

-include("quic.hrl").

% 10MB
-define(DEFAULT_DATA_SIZE, 10485760).
% QUIC default MTU
-define(DEFAULT_PACKET_SIZE, 1200).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Run the full benchmark with default options.
run() ->
    run(#{data_size => ?DEFAULT_DATA_SIZE}).

%% @doc Run the benchmark with custom options.
%% Options:
%%   data_size => integer() - Total bytes to transfer (default 10MB)
%%   packet_size => integer() - Size of each packet (default 1200)
%%   iterations => integer() - Number of iterations (default 3)
run(Opts) ->
    DataSize = maps:get(data_size, Opts, ?DEFAULT_DATA_SIZE),
    PacketSize = maps:get(packet_size, Opts, ?DEFAULT_PACKET_SIZE),
    Iterations = maps:get(iterations, Opts, 3),

    io:format("~n=== UDP Packet Batching Benchmark ===~n"),
    io:format("Platform: ~p~n", [os:type()]),
    io:format("OTP Release: ~s~n", [erlang:system_info(otp_release)]),
    io:format("Capabilities: ~p~n", [quic_socket:detect_capabilities()]),
    io:format("~nTest Parameters:~n"),
    io:format("  Data size: ~.2f MB~n", [DataSize / 1048576]),
    io:format("  Packet size: ~p bytes~n", [PacketSize]),
    io:format("  Iterations: ~p~n", [Iterations]),

    %% Run benchmark iterations
    NoBatchResults = run_iterations(Iterations, DataSize, PacketSize, false),
    BatchResults = run_iterations(Iterations, DataSize, PacketSize, true),

    %% Calculate statistics
    NoBatchAvg = lists:sum(NoBatchResults) / Iterations,
    BatchAvg = lists:sum(BatchResults) / Iterations,

    DataSizeMB = DataSize / 1048576,
    NoBatchMBps = DataSizeMB / (NoBatchAvg / 1000000),
    BatchMBps = DataSizeMB / (BatchAvg / 1000000),

    Improvement =
        case NoBatchAvg of
            0 -> 0;
            _ -> (NoBatchAvg - BatchAvg) / NoBatchAvg * 100
        end,

    io:format("~n=== Results ===~n"),
    io:format("No batching:   ~.2f MB/s (avg ~.1f ms)~n", [NoBatchMBps, NoBatchAvg / 1000]),
    io:format("With batching: ~.2f MB/s (avg ~.1f ms)~n", [BatchMBps, BatchAvg / 1000]),
    io:format("Improvement:   ~.1f%~n", [Improvement]),

    #{
        no_batch_mbps => NoBatchMBps,
        batch_mbps => BatchMBps,
        improvement_pct => Improvement,
        platform => os:type(),
        capabilities => quic_socket:detect_capabilities()
    }.

%% @doc Quick benchmark with smaller data size.
quick() ->
    % 1MB, 1 iteration
    run(#{data_size => 1048576, iterations => 1}).

%%====================================================================
%% Internal Functions
%%====================================================================

run_iterations(N, DataSize, PacketSize, Batching) ->
    io:format(
        "~nRunning ~p iterations (~s)...~n",
        [
            N,
            case Batching of
                true -> "batching";
                false -> "no batching"
            end
        ]
    ),
    [
        begin
            {Time, _} = timer:tc(fun() -> run_transfer(DataSize, PacketSize, Batching) end),
            io:format("  Iteration ~p: ~.1f ms~n", [I, Time / 1000]),
            Time
        end
     || I <- lists:seq(1, N)
    ].

run_transfer(DataSize, PacketSize, Batching) ->
    %% Create sender and receiver sockets
    {ok, Sender} = quic_socket:open(0, #{
        batching => #{enabled => Batching, max_packets => 64}
    }),
    {ok, Receiver} = quic_socket:open(0, #{
        batching => #{enabled => false}
    }),

    {ok, {RecvIP, RecvPort}} = quic_socket:sockname(Receiver),

    %% Set receiver to active mode
    quic_socket:setopts(Receiver, [{active, true}]),

    %% Generate test data
    Packet = binary:copy(<<0>>, PacketSize),
    NumPackets = DataSize div PacketSize,

    %% Start receiver counter
    ReceiverPid = spawn_link(fun() -> receiver_loop(0, NumPackets) end),

    %% Send all packets
    FinalState = send_packets(Sender, RecvIP, RecvPort, Packet, NumPackets),

    %% Flush any remaining batched packets
    {ok, _} = quic_socket:flush(FinalState),

    %% Wait for receiver to finish
    receive
        {receiver_done, Count} ->
            ok = quic_socket:close(FinalState),
            ok = quic_socket:close(Receiver),
            Count
    after 10000 ->
        ReceiverPid ! stop,
        ok = quic_socket:close(FinalState),
        ok = quic_socket:close(Receiver),
        timeout
    end.

send_packets(State, _IP, _Port, _Packet, 0) ->
    State;
send_packets(State, IP, Port, Packet, N) ->
    {ok, NewState} = quic_socket:send(State, IP, Port, Packet),
    send_packets(NewState, IP, Port, Packet, N - 1).

receiver_loop(Count, Target) when Count >= Target ->
    %% Drain any remaining packets
    drain_remaining(Count, Target);
receiver_loop(Count, Target) ->
    receive
        {udp, _, _, _, _} ->
            receiver_loop(Count + 1, Target);
        stop ->
            ok
    after 1000 ->
        %% Timeout - report what we got
        self() ! {receiver_done, Count}
    end.

drain_remaining(Count, Target) ->
    receive
        {udp, _, _, _, _} ->
            drain_remaining(Count + 1, Target)
    after 100 ->
        %% Report to parent
        case get('$ancestors') of
            [Parent | _] -> Parent ! {receiver_done, Count};
            _ -> ok
        end
    end.
