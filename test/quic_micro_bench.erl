%%% -*- erlang -*-
%%%
%%% QUIC Microbenchmark Module
%%%
%%% Isolated performance tests for ACK processing, reassembly, and frame parsing.
%%% Used to identify O(n) scaling issues causing throughput degradation.
%%%
%%% Usage:
%%%   quic_micro_bench:run().                      % Run all benchmarks
%%%   quic_micro_bench:bench_ack_processing().     % ACK processing only
%%%   quic_micro_bench:bench_reassembly().         % Reassembly only
%%%   quic_micro_bench:bench_frame_parsing().      % Frame parsing only
%%%

-module(quic_micro_bench).

-export([
    run/0,
    bench_ack_processing/0,
    bench_ack_processing/1,
    bench_reassembly/0,
    bench_reassembly/1,
    bench_frame_parsing/0,
    bench_frame_parsing/1,
    bench_loss_detection/0,
    bench_loss_detection/1,
    bench_incremental_acks/0,
    bench_incremental_acks/1
]).

-include("quic.hrl").

%%====================================================================
%% Public API
%%====================================================================

%% @doc Run all microbenchmarks at various scales
-spec run() -> ok.
run() ->
    io:format("~n=== QUIC Microbenchmarks ===~n~n"),

    %% Test scales: 100, 1K, 10K, 20K packets (20K ~= 10MB transfer at 1100 bytes)
    Scales = [100, 1000, 10000, 20000],

    io:format("--- ACK Processing ---~n"),
    run_scaled(fun bench_ack_processing/1, Scales),

    io:format("~n--- Loss Detection ---~n"),
    run_scaled(fun bench_loss_detection/1, Scales),

    io:format("~n--- Incremental ACKs (transfer simulation) ---~n"),
    TransferScales = [1000, 5000, 10000],
    run_scaled(fun bench_incremental_acks/1, TransferScales),

    io:format("~n--- Binary Reassembly ---~n"),
    FragmentScales = [100, 1000, 5000, 10000],
    run_scaled(fun bench_reassembly/1, FragmentScales),

    io:format("~n--- Frame Parsing ---~n"),
    FrameScales = [10, 50, 100],
    run_scaled(fun bench_frame_parsing/1, FrameScales),

    io:format("~n=== Benchmark Complete ===~n"),
    ok.

run_scaled(BenchFun, Scales) ->
    %% Warmup run for JIT
    _ = BenchFun(lists:max(Scales)),

    Results = lists:map(
        fun(Scale) ->
            %% Run 3 iterations and take median
            Times = [
                begin
                    {Time, _} = timer:tc(fun() -> BenchFun(Scale) end),
                    Time / 1000
                end
             || _ <- [1, 2, 3]
            ],
            TimeMs = lists:nth(2, lists:sort(Times)),
            io:format("  ~6w items: ~8.2f ms~n", [Scale, TimeMs]),
            {Scale, TimeMs}
        end,
        Scales
    ),
    %% Check for O(n^2) scaling
    case length(Results) >= 2 of
        true ->
            %% Compare last two results for better scaling analysis
            [{S1, T1}, {S2, T2} | _] = lists:reverse(Results),
            ScaleRatio = S2 / S1,
            TimeRatio = T2 / max(0.001, T1),
            io:format(
                "  Scaling ~w->~w: ~.1fx items -> ~.1fx time (linear=~.1fx)~n",
                [S1, S2, ScaleRatio, TimeRatio, ScaleRatio]
            ),
            %% Show per-item cost
            PerItemUs1 = (T1 * 1000) / S1,
            PerItemUs2 = (T2 * 1000) / S2,
            io:format(
                "  Per-item: ~.2f us @ ~w, ~.2f us @ ~w~n",
                [PerItemUs1, S1, PerItemUs2, S2]
            );
        false ->
            ok
    end.

%%====================================================================
%% ACK Processing Benchmark
%%====================================================================

%% @doc Benchmark ACK processing with default scale
-spec bench_ack_processing() -> map().
bench_ack_processing() ->
    bench_ack_processing(1000).

%% @doc Benchmark ACK processing at specific packet count
%% Simulates processing ACK for packets 0 to N-1
-spec bench_ack_processing(pos_integer()) -> map().
bench_ack_processing(PacketCount) ->
    %% Build loss state by sending packets through the API
    LossState0 = quic_loss:new(),
    LossState = build_loss_state(LossState0, 0, PacketCount),

    %% Create ACK frame acknowledging all packets
    %% ACK frame: {ack, LargestAcked, AckDelay, FirstRange, AckRanges}
    LargestAcked = PacketCount - 1,
    FirstRange = PacketCount - 1,
    AckFrame = {ack, LargestAcked, 0, FirstRange, []},

    Now = erlang:monotonic_time(millisecond),

    %% Time ACK processing
    {Time, {NewState, AckedPackets, LostPackets, _AckMeta}} = timer:tc(
        fun() -> quic_loss:on_ack_received(LossState, AckFrame, Now) end
    ),

    #{
        packet_count => PacketCount,
        time_us => Time,
        acked_count => length(AckedPackets),
        lost_count => length(LostPackets),
        remaining => map_size(quic_loss:sent_packets(NewState))
    }.

%% Build loss state by recording sent packets
build_loss_state(State, PN, Max) when PN >= Max ->
    State;
build_loss_state(State, PN, Max) ->
    NewState = quic_loss:on_packet_sent(State, PN, 1100, true, []),
    build_loss_state(NewState, PN + 1, Max).

%%====================================================================
%% Incremental ACK Benchmark (Transfer Simulation)
%%====================================================================

%% @doc Benchmark incremental ACK processing with default scale
-spec bench_incremental_acks() -> map().
bench_incremental_acks() ->
    bench_incremental_acks(5000).

%% @doc Benchmark incremental ACK processing simulating a real transfer.
%% Sends N packets, then processes ACKs for batches of packets.
%% This tests the cumulative O(n) effect over many ACK frames.
-spec bench_incremental_acks(pos_integer()) -> map().
bench_incremental_acks(TotalPackets) ->
    %% Simulate sending packets in batches, with ACKs arriving periodically
    %% ACK every 10 packets (similar to real world ACK frequency)
    AckEvery = 10,
    NumAcks = TotalPackets div AckEvery,

    %% Start with empty state
    LossState0 = quic_loss:new(),

    %% Send all packets first
    LossState1 = build_loss_state(LossState0, 0, TotalPackets),

    %% Now process incremental ACKs and measure total time
    Now = erlang:monotonic_time(millisecond),
    {Time, FinalState} = timer:tc(
        fun() -> process_incremental_acks(LossState1, 0, TotalPackets, AckEvery, Now) end
    ),

    #{
        total_packets => TotalPackets,
        num_acks => NumAcks,
        time_us => Time,
        remaining => map_size(quic_loss:sent_packets(FinalState)),
        time_per_ack_us => Time / NumAcks
    }.

%% Process ACKs incrementally
process_incremental_acks(State, Acked, TotalPackets, _AckEvery, _Now) when Acked >= TotalPackets ->
    State;
process_incremental_acks(State, Acked, TotalPackets, AckEvery, Now) ->
    %% ACK the next batch
    LargestAcked = min(Acked + AckEvery - 1, TotalPackets - 1),
    FirstRange = min(AckEvery - 1, LargestAcked - Acked),
    AckFrame = {ack, LargestAcked, 0, FirstRange, []},

    {NewState, _AckedPackets, _LostPackets, _AckMeta} =
        quic_loss:on_ack_received(State, AckFrame, Now),

    process_incremental_acks(NewState, LargestAcked + 1, TotalPackets, AckEvery, Now).

%%====================================================================
%% Loss Detection Benchmark
%%====================================================================

%% @doc Benchmark loss detection with default scale
-spec bench_loss_detection() -> map().
bench_loss_detection() ->
    bench_loss_detection(1000).

%% @doc Benchmark loss detection at specific packet count
%% Simulates detecting lost packets
-spec bench_loss_detection(pos_integer()) -> map().
bench_loss_detection(PacketCount) ->
    %% Build loss state
    LossState0 = quic_loss:new(),
    LossState = build_loss_state(LossState0, 0, PacketCount),

    %% Simulate that packet PacketCount-1 was just acknowledged
    %% This makes earlier packets candidates for loss based on packet threshold
    LargestAcked = PacketCount - 1,

    %% Time loss detection
    {Time, {NewState, LostPackets}} = timer:tc(
        fun() -> quic_loss:detect_lost_packets(LossState, LargestAcked) end
    ),

    #{
        packet_count => PacketCount,
        time_us => Time,
        lost_count => length(LostPackets),
        remaining => map_size(quic_loss:sent_packets(NewState))
    }.

%%====================================================================
%% Binary Reassembly Benchmark
%%====================================================================

%% @doc Benchmark binary reassembly with default scale
-spec bench_reassembly() -> map().
bench_reassembly() ->
    bench_reassembly(1000).

%% @doc Benchmark reassembly at specific fragment count
%% Compares binary append vs iolist approaches
-spec bench_reassembly(pos_integer()) -> map().
bench_reassembly(FragmentCount) ->
    %% Generate fragments of typical QUIC stream data size
    FragmentSize = 1100,
    Fragments = [crypto:strong_rand_bytes(FragmentSize) || _ <- lists:seq(1, FragmentCount)],

    %% Build in-order buffer (offset -> data)
    Buffer = build_fragment_buffer(Fragments, 0, #{}),

    %% Benchmark 1: Binary append (current implementation)
    {TimeBinary, {DataBinary, _, _}} = timer:tc(
        fun() -> extract_contiguous_binary(Buffer, 0) end
    ),

    %% Benchmark 2: IOList approach (alternative)
    {TimeIOList, DataIOList} = timer:tc(
        fun() -> extract_contiguous_iolist(Buffer, 0, FragmentCount * FragmentSize) end
    ),

    %% Verify results match
    DataIOListBin = iolist_to_binary(DataIOList),
    true = DataBinary =:= DataIOListBin,

    #{
        fragment_count => FragmentCount,
        fragment_size => FragmentSize,
        total_bytes => FragmentCount * FragmentSize,
        binary_append_us => TimeBinary,
        iolist_us => TimeIOList,
        ratio => TimeBinary / max(1, TimeIOList)
    }.

%% Binary append implementation (mirrors quic_connection:extract_contiguous_data)
extract_contiguous_binary(Buffer, Offset) ->
    extract_contiguous_binary(Buffer, Offset, <<>>).

extract_contiguous_binary(Buffer, Offset, Acc) ->
    case maps:take(Offset, Buffer) of
        {Data, NewBuffer} ->
            NextOffset = Offset + byte_size(Data),
            extract_contiguous_binary(NewBuffer, NextOffset, <<Acc/binary, Data/binary>>);
        error ->
            {Acc, Offset, Buffer}
    end.

%% IOList implementation (alternative approach)
extract_contiguous_iolist(Buffer, Offset, ExpectedSize) ->
    extract_contiguous_iolist(Buffer, Offset, ExpectedSize, []).

extract_contiguous_iolist(Buffer, Offset, ExpectedSize, Acc) ->
    case maps:get(Offset, Buffer, undefined) of
        undefined ->
            lists:reverse(Acc);
        Data when Offset + byte_size(Data) >= ExpectedSize ->
            lists:reverse([Data | Acc]);
        Data ->
            extract_contiguous_iolist(Buffer, Offset + byte_size(Data), ExpectedSize, [Data | Acc])
    end.

%%====================================================================
%% Frame Parsing Benchmark
%%====================================================================

%% @doc Benchmark frame parsing with default scale
-spec bench_frame_parsing() -> map().
bench_frame_parsing() ->
    bench_frame_parsing(50).

%% @doc Benchmark frame parsing at specific frame count per packet
%% Tests decode_all/1 vs streaming decode
-spec bench_frame_parsing(pos_integer()) -> map().
bench_frame_parsing(FrameCount) ->
    %% Build a packet payload with multiple STREAM frames
    StreamId = 4,
    Frames = [build_stream_frame(StreamId, I * 100, 100) || I <- lists:seq(0, FrameCount - 1)],
    Payload = iolist_to_binary(Frames),

    %% Benchmark decode_all
    {TimeDecodeAll, {ok, DecodedFrames}} = timer:tc(
        fun() -> quic_frame:decode_all(Payload) end
    ),

    %% Benchmark streaming decode (decode + process immediately)
    {TimeStreaming, StreamCount} = timer:tc(
        fun() -> decode_streaming(Payload, 0) end
    ),

    #{
        frame_count => FrameCount,
        payload_size => byte_size(Payload),
        decoded_count => length(DecodedFrames),
        decode_all_us => TimeDecodeAll,
        streaming_us => TimeStreaming,
        ratio => TimeDecodeAll / max(1, TimeStreaming),
        streaming_count => StreamCount
    }.

%% Streaming decode (process each frame immediately)
decode_streaming(<<>>, Count) ->
    Count;
decode_streaming(Bin, Count) ->
    case quic_frame:decode(Bin) of
        {error, _} ->
            Count;
        {_Frame, Rest} ->
            %% In real code, we'd process the frame here
            decode_streaming(Rest, Count + 1)
    end.

%%====================================================================
%% Helper Functions
%%====================================================================

%% Build fragment buffer
build_fragment_buffer([], _Offset, Acc) ->
    Acc;
build_fragment_buffer([Data | Rest], Offset, Acc) ->
    build_fragment_buffer(Rest, Offset + byte_size(Data), maps:put(Offset, Data, Acc)).

%% Build a STREAM frame binary using quic_frame:encode
build_stream_frame(StreamId, Offset, DataSize) ->
    Data = crypto:strong_rand_bytes(DataSize),
    quic_frame:encode({stream, StreamId, Offset, Data, false}).
