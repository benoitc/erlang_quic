%%% -*- erlang -*-
%%%
%%% Example: Echo Client
%%%
%%% Usage:
%%%   1. Start server: echo_server:start(4433).
%%%   2. Run client: echo_client:run("localhost", 4433, <<"Hello!">>).
%%%   3. Send datagram: echo_client:datagram("localhost", 4433, <<"Fast!">>).
%%%

-module(echo_client).

-export([run/3, datagram/3, benchmark/4]).

%% @doc Send data to echo server and receive response.
-spec run(string() | binary(), inet:port_number(), binary()) ->
    {ok, binary()} | {error, term()}.
run(Host, Port, Data) ->
    application:ensure_all_started(quic),

    io:format("Connecting to ~s:~p~n", [Host, Port]),

    Opts = #{
        alpn => [<<"echo">>],
        verify => false,
        max_datagram_frame_size => 65535
    },

    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            Result = do_echo(ConnRef, Data),
            quic:close(ConnRef, normal),
            Result;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

%% @doc Send a datagram and wait for response.
-spec datagram(string() | binary(), inet:port_number(), binary()) ->
    {ok, binary()} | {error, term()}.
datagram(Host, Port, Data) ->
    application:ensure_all_started(quic),

    Opts = #{
        alpn => [<<"echo">>],
        verify => false,
        max_datagram_frame_size => 65535
    },

    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            Result = do_datagram_echo(ConnRef, Data),
            quic:close(ConnRef, normal),
            Result;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

%% @doc Simple benchmark - send N messages and measure throughput.
-spec benchmark(string() | binary(), inet:port_number(), binary(), pos_integer()) ->
    {ok, map()} | {error, term()}.
benchmark(Host, Port, Data, Count) ->
    application:ensure_all_started(quic),

    Opts = #{
        alpn => [<<"echo">>],
        verify => false
    },

    case quic:connect(Host, Port, Opts, self()) of
        {ok, ConnRef} ->
            Result = run_benchmark(ConnRef, Data, Count),
            quic:close(ConnRef, normal),
            Result;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

do_echo(ConnRef, Data) ->
    %% Wait for connection
    receive
        {quic, ConnRef, {connected, Info}} ->
            io:format("Connected! ALPN: ~p~n", [maps:get(alpn_protocol, Info, unknown)]);
        {quic, ConnRef, {closed, Reason}} ->
            exit({connection_closed, Reason})
    after 5000 ->
        exit(connection_timeout)
    end,

    %% Open stream and send data
    {ok, StreamId} = quic:open_stream(ConnRef),
    io:format("Opened stream ~p~n", [StreamId]),

    ok = quic:send_data(ConnRef, StreamId, Data, true),
    io:format("Sent ~p bytes~n", [byte_size(Data)]),

    %% Receive response
    Response = receive_stream_data(ConnRef, StreamId, <<>>, 5000),
    io:format("Received ~p bytes~n", [byte_size(Response)]),

    case Response =:= Data of
        true -> {ok, Response};
        false -> {error, {mismatch, Data, Response}}
    end.

do_datagram_echo(ConnRef, Data) ->
    %% Wait for connection
    receive
        {quic, ConnRef, {connected, _}} ->
            ok
    after 5000 ->
        exit(connection_timeout)
    end,

    %% Check datagram support
    MaxSize = quic:datagram_max_size(ConnRef),
    case MaxSize of
        0 ->
            {error, datagrams_not_supported};
        _ when byte_size(Data) > MaxSize ->
            {error, {datagram_too_large, MaxSize}};
        _ ->
            %% Send datagram
            ok = quic:send_datagram(ConnRef, Data),
            io:format("Sent datagram: ~p bytes~n", [byte_size(Data)]),

            %% Wait for response
            receive
                {quic, ConnRef, {datagram, Response}} ->
                    io:format("Received datagram: ~p bytes~n", [byte_size(Response)]),
                    {ok, Response}
            after 5000 ->
                {error, timeout}
            end
    end.

receive_stream_data(ConnRef, StreamId, Acc, Timeout) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, ConnRef, {stream_data, StreamId, Data, false}} ->
            receive_stream_data(ConnRef, StreamId, <<Acc/binary, Data/binary>>, Timeout);
        {quic, ConnRef, {closed, _}} ->
            Acc
    after Timeout ->
        io:format("Timeout waiting for data, have ~p bytes~n", [byte_size(Acc)]),
        Acc
    end.

run_benchmark(ConnRef, Data, Count) ->
    %% Wait for connection
    receive
        {quic, ConnRef, {connected, _}} -> ok
    after 5000 ->
        exit(connection_timeout)
    end,

    DataSize = byte_size(Data),
    io:format("Starting benchmark: ~p requests, ~p bytes each~n", [Count, DataSize]),

    Start = erlang:monotonic_time(millisecond),

    %% Send all requests on parallel streams
    StreamIds = lists:map(fun(_) ->
        {ok, StreamId} = quic:open_stream(ConnRef),
        ok = quic:send_data(ConnRef, StreamId, Data, true),
        StreamId
    end, lists:seq(1, Count)),

    %% Receive all responses
    Responses = lists:map(fun(StreamId) ->
        receive_stream_data(ConnRef, StreamId, <<>>, 30000)
    end, StreamIds),

    End = erlang:monotonic_time(millisecond),
    Duration = End - Start,

    TotalBytes = DataSize * Count * 2,  % sent + received
    Throughput = (TotalBytes * 1000) div max(Duration, 1),

    Successful = length([R || R <- Responses, R =:= Data]),

    Result = #{
        total_requests => Count,
        successful => Successful,
        failed => Count - Successful,
        duration_ms => Duration,
        bytes_transferred => TotalBytes,
        throughput_bytes_sec => Throughput
    },

    io:format("Benchmark results:~n"),
    io:format("  Requests: ~p successful, ~p failed~n", [Successful, Count - Successful]),
    io:format("  Duration: ~p ms~n", [Duration]),
    io:format("  Throughput: ~p bytes/sec~n", [Throughput]),

    {ok, Result}.
