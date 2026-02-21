%%% -*- erlang -*-
%%%
%%% PropEr tests for QUIC Reliability (Streams, ACK, Loss, CC, Flow)
%%%

-module(prop_quic_reliability).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Generators
%%====================================================================

%% Stream ID
stream_id() ->
    ?LET(
        Base,
        range(0, 1000),
        ?LET(
            Type,
            range(0, 3),
            Base * 4 + Type
        )
    ).

%% Data chunk
data_chunk() ->
    ?LET(Len, range(1, 1000), binary(Len)).

%% Packet number
packet_number() ->
    range(0, 10000).

%% Packet size
packet_size() ->
    range(100, 1500).

%% Role
role() ->
    oneof([client, server]).

%% Flow control limit
flow_limit() ->
    range(1000, 10000000).

%%====================================================================
%% Stream Properties
%%====================================================================

%% Stream send/receive roundtrip
prop_stream_data_roundtrip() ->
    ?FORALL(
        {StreamId, Data, Role},
        {stream_id(), data_chunk(), role()},
        begin
            Stream = quic_stream:new(StreamId, Role),
            {ok, S1} = quic_stream:send(Stream, Data),
            {SendData, _Offset, _Fin, S2} = quic_stream:get_send_data(S1, byte_size(Data)),
            SendData =:= Data andalso quic_stream:bytes_to_send(S2) =:= 0
        end
    ).

%% Stream receive reassembly (in order)
prop_stream_receive_in_order() ->
    ?FORALL(
        {StreamId, Chunks, Role},
        {stream_id(), non_empty(list(data_chunk())), role()},
        begin
            Stream = quic_stream:new(StreamId, Role),
            %% Only test on streams where we can receive (not local uni)
            IsLocal = quic_stream:is_local(Stream, Role),
            IsBidi = quic_stream:is_bidi(Stream),
            CanReceive = not IsLocal orelse IsBidi,
            case CanReceive of
                true ->
                    {FinalStream, _TotalOffset} = lists:foldl(
                        fun(Chunk, {S, Offset}) ->
                            {ok, S1} = quic_stream:receive_data(S, Offset, Chunk, false),
                            {S1, Offset + byte_size(Chunk)}
                        end,
                        {Stream, 0},
                        Chunks
                    ),
                    ExpectedData = iolist_to_binary(Chunks),
                    TotalSize = byte_size(ExpectedData),
                    %% Check bytes available before read
                    BytesBefore = quic_stream:bytes_available(FinalStream),
                    {ReceivedData, StreamAfterRead} = quic_stream:read(FinalStream),
                    %% Check bytes available after read
                    BytesAfter = quic_stream:bytes_available(StreamAfterRead),
                    ReceivedData =:= ExpectedData andalso
                        BytesBefore =:= TotalSize andalso
                        BytesAfter =:= 0;
                false ->
                    %% Local uni stream can't receive - skip
                    true
            end
        end
    ).

%% Stream state transitions are valid
prop_stream_state_transitions() ->
    ?FORALL(
        {StreamId, Role},
        {stream_id(), role()},
        begin
            Stream = quic_stream:new(StreamId, Role),
            %% Local stream starts open
            IsLocal = quic_stream:is_local(Stream, Role),
            InitState = quic_stream:state(Stream),
            case IsLocal of
                true -> InitState =:= open;
                false -> InitState =:= idle
            end
        end
    ).

%% Stream ID type detection
prop_stream_id_type() ->
    ?FORALL(
        StreamId,
        stream_id(),
        begin
            Stream = quic_stream:new(StreamId, client),
            IsBidi = quic_stream:is_bidi(Stream),
            %% Bit 1 determines bidi (0) vs uni (1)
            ExpectedBidi = (StreamId band 2) =:= 0,
            IsBidi =:= ExpectedBidi
        end
    ).

%% FIN closes appropriate side (only test on local streams)
prop_stream_fin_closes() ->
    ?FORALL(
        {StreamId, Role},
        {stream_id(), role()},
        begin
            Stream = quic_stream:new(StreamId, Role),
            IsLocal = quic_stream:is_local(Stream, Role),
            IsBidi = quic_stream:is_bidi(Stream),
            %% Only test send_fin on streams where we can send:
            %% - Local streams (we initiated)
            %% - For remote uni streams, we can't send (skip test)
            CanSend = IsLocal orelse IsBidi,
            case CanSend andalso IsLocal of
                true ->
                    %% Local stream starts open, can send FIN
                    {ok, S1} = quic_stream:send_fin(Stream),
                    quic_stream:is_send_closed(S1) andalso
                        not quic_stream:is_recv_closed(S1);
                false ->
                    %% Remote stream - skip test (not meaningful)
                    true
            end
        end
    ).

%%====================================================================
%% ACK Properties
%%====================================================================

%% Recording packets creates ranges
prop_ack_records_packets() ->
    ?FORALL(
        PNs,
        non_empty(list(packet_number())),
        begin
            State = quic_ack:new(),
            FinalState = lists:foldl(
                fun(PN, S) -> quic_ack:record_received(S, PN) end,
                State,
                PNs
            ),
            Largest = quic_ack:largest_received(FinalState),
            Largest =:= lists:max(PNs)
        end
    ).

%% ACK generation for recorded packets
prop_ack_generation() ->
    ?FORALL(
        PNs,
        non_empty(list(packet_number())),
        begin
            State = quic_ack:new(),
            FinalState = lists:foldl(
                fun(PN, S) -> quic_ack:record_received(S, PN, true) end,
                State,
                PNs
            ),
            case quic_ack:generate_ack(FinalState) of
                {ok, {ack, Largest, _, _, _}} ->
                    Largest =:= lists:max(PNs);
                _ ->
                    false
            end
        end
    ).

%% Sequential packets form single range
prop_ack_sequential_single_range() ->
    ?FORALL(
        Start,
        range(0, 1000),
        begin
            PNs = lists:seq(Start, Start + 10),
            State = quic_ack:new(),
            FinalState = lists:foldl(
                fun(PN, S) -> quic_ack:record_received(S, PN) end,
                State,
                PNs
            ),
            Ranges = quic_ack:ack_ranges(FinalState),
            length(Ranges) =:= 1
        end
    ).

%% Gaps create multiple ranges
prop_ack_gaps_multiple_ranges() ->
    ?FORALL(
        {Start, Gap},
        {range(0, 100), range(2, 10)},
        begin
            %% Create two separate ranges with a gap
            PNs = lists:seq(Start, Start + 5) ++ lists:seq(Start + 5 + Gap, Start + 10 + Gap),
            State = quic_ack:new(),
            FinalState = lists:foldl(
                fun(PN, S) -> quic_ack:record_received(S, PN) end,
                State,
                PNs
            ),
            Ranges = quic_ack:ack_ranges(FinalState),
            length(Ranges) >= 2
        end
    ).

%%====================================================================
%% Loss Detection Properties
%%====================================================================

%% Sending packets increases bytes in flight
prop_loss_bytes_in_flight() ->
    ?FORALL(
        Sizes,
        non_empty(list(packet_size())),
        begin
            State = quic_loss:new(),
            {FinalState, _} = lists:foldl(
                fun(Size, {S, PN}) ->
                    {quic_loss:on_packet_sent(S, PN, Size, true), PN + 1}
                end,
                {State, 0},
                Sizes
            ),
            quic_loss:bytes_in_flight(FinalState) =:= lists:sum(Sizes)
        end
    ).

%% RTT update changes smoothed RTT
prop_loss_rtt_update() ->
    ?FORALL(
        RTT,
        range(10, 500),
        begin
            State = quic_loss:new(),
            S1 = quic_loss:update_rtt(State, RTT, 0),
            %% First sample sets smoothed_rtt directly
            quic_loss:smoothed_rtt(S1) =:= RTT
        end
    ).

%% PTO increases with count
prop_loss_pto_backoff() ->
    ?FORALL(
        _,
        exactly(true),
        begin
            State = quic_loss:new(),
            PTO0 = quic_loss:get_pto(State),
            S1 = quic_loss:on_pto_expired(State),
            PTO1 = quic_loss:get_pto(S1),
            S2 = quic_loss:on_pto_expired(S1),
            PTO2 = quic_loss:get_pto(S2),
            PTO1 =:= PTO0 * 2 andalso PTO2 =:= PTO0 * 4
        end
    ).

%%====================================================================
%% Congestion Control Properties
%%====================================================================

%% Initial cwnd is positive
prop_cc_initial_cwnd() ->
    ?FORALL(
        _,
        exactly(true),
        begin
            State = quic_cc:new(),
            quic_cc:cwnd(State) > 0
        end
    ).

%% Slow start increases cwnd
prop_cc_slow_start_increases() ->
    ?FORALL(
        AckedBytes,
        range(1000, 5000),
        begin
            State = quic_cc:new(),
            InitCwnd = quic_cc:cwnd(State),
            S1 = quic_cc:on_packet_sent(State, AckedBytes),
            S2 = quic_cc:on_packets_acked(S1, AckedBytes),
            quic_cc:cwnd(S2) =:= InitCwnd + AckedBytes
        end
    ).

%% Congestion event reduces cwnd
prop_cc_congestion_reduces() ->
    ?FORALL(
        _,
        exactly(true),
        begin
            State = quic_cc:new(),
            InitCwnd = quic_cc:cwnd(State),
            Now = erlang:monotonic_time(millisecond),
            S1 = quic_cc:on_congestion_event(State, Now),
            quic_cc:cwnd(S1) < InitCwnd
        end
    ).

%% Bytes in flight tracking
prop_cc_bytes_tracking() ->
    ?FORALL(
        Sizes,
        non_empty(list(packet_size())),
        begin
            State = quic_cc:new(),
            FinalState = lists:foldl(
                fun(Size, S) -> quic_cc:on_packet_sent(S, Size) end,
                State,
                Sizes
            ),
            quic_cc:bytes_in_flight(FinalState) =:= lists:sum(Sizes)
        end
    ).

%%====================================================================
%% Flow Control Properties
%%====================================================================

%% Send within limit succeeds
prop_flow_send_within_limit() ->
    ?FORALL(
        {Limit, Size},
        {flow_limit(), packet_size()},
        ?IMPLIES(
            Size < Limit,
            begin
                State = quic_flow:new(#{peer_initial_max_data => Limit}),
                quic_flow:can_send(State, Size)
            end
        )
    ).

%% Send exceeding limit fails
prop_flow_send_exceeds_limit() ->
    ?FORALL(
        {Limit, Extra},
        {flow_limit(), range(1, 1000)},
        begin
            State = quic_flow:new(#{peer_initial_max_data => Limit}),
            not quic_flow:can_send(State, Limit + Extra)
        end
    ).

%% Receive within limit succeeds
prop_flow_receive_within_limit() ->
    ?FORALL(
        {Limit, Size},
        {flow_limit(), packet_size()},
        ?IMPLIES(
            Size < Limit,
            begin
                State = quic_flow:new(#{initial_max_data => Limit}),
                case quic_flow:on_data_received(State, Size) of
                    {ok, _} -> true;
                    _ -> false
                end
            end
        )
    ).

%% Receive exceeding limit fails
prop_flow_receive_exceeds_limit() ->
    ?FORALL(
        {Limit, Extra},
        {flow_limit(), range(1, 1000)},
        begin
            State = quic_flow:new(#{initial_max_data => Limit}),
            {ok, S1} = quic_flow:on_data_received(State, Limit),
            quic_flow:on_data_received(S1, Extra) =:= {error, flow_control_error}
        end
    ).

%% MAX_DATA increases limit
prop_flow_max_data_increases() ->
    ?FORALL(
        {Initial, Increase},
        {flow_limit(), flow_limit()},
        begin
            State = quic_flow:new(#{peer_initial_max_data => Initial}),
            S1 = quic_flow:on_max_data_received(State, Initial + Increase),
            quic_flow:send_limit(S1) =:= Initial + Increase
        end
    ).

%%====================================================================
%% EUnit wrapper
%%====================================================================

proper_test_() ->
    {timeout, 300, [
        %% Stream tests
        ?_assert(
            proper:quickcheck(prop_stream_data_roundtrip(), [{numtests, 200}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_stream_receive_in_order(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_stream_state_transitions(), [{numtests, 200}, {to_file, user}])
        ),
        ?_assert(proper:quickcheck(prop_stream_id_type(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_stream_fin_closes(), [{numtests, 100}, {to_file, user}])),
        %% ACK tests
        ?_assert(proper:quickcheck(prop_ack_records_packets(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_ack_generation(), [{numtests, 200}, {to_file, user}])),
        ?_assert(
            proper:quickcheck(prop_ack_sequential_single_range(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_ack_gaps_multiple_ranges(), [{numtests, 100}, {to_file, user}])
        ),
        %% Loss detection tests
        ?_assert(
            proper:quickcheck(prop_loss_bytes_in_flight(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(proper:quickcheck(prop_loss_rtt_update(), [{numtests, 100}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_loss_pto_backoff(), [{numtests, 50}, {to_file, user}])),
        %% Congestion control tests
        ?_assert(proper:quickcheck(prop_cc_initial_cwnd(), [{numtests, 50}, {to_file, user}])),
        ?_assert(
            proper:quickcheck(prop_cc_slow_start_increases(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_cc_congestion_reduces(), [{numtests, 50}, {to_file, user}])
        ),
        ?_assert(proper:quickcheck(prop_cc_bytes_tracking(), [{numtests, 100}, {to_file, user}])),
        %% Flow control tests
        ?_assert(
            proper:quickcheck(prop_flow_send_within_limit(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_flow_send_exceeds_limit(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_flow_receive_within_limit(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_flow_receive_exceeds_limit(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_flow_max_data_increases(), [{numtests, 100}, {to_file, user}])
        )
    ]}.
