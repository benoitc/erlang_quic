%%% -*- erlang -*-
%%%
%%% HTTP/3 transfers through a small receive window.
%%%
%%% A receiver keeps granting credit as it receives, whatever its
%%% `max_receive_window'. Each stream used to track the other
%%% bidirectional limit than the one it advertised, so with a small
%%% maximum window it never saw its headroom run low: the transfer
%%% stopped after the first window and the sender's writes sat queued.
%%%
%%% Server and client run in this VM over 127.0.0.1.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_receive_window_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    response_through_64k_window_capped_at_128k/1,
    response_through_128k_window_capped_at_256k/1,
    response_larger_than_the_send_queue_through_200k_window/1,
    response_through_1m_window_capped_at_2m/1,
    upload_through_64k_window_capped_at_128k/1
]).

-define(MIB, (1024 * 1024)).
-define(PIECE, 65536).
-define(WAIT_MS, 10000).

suite() ->
    [{timetrap, {seconds, 120}}].

all() ->
    [
        response_through_64k_window_capped_at_128k,
        response_through_128k_window_capped_at_256k,
        response_larger_than_the_send_queue_through_200k_window,
        response_through_1m_window_capped_at_2m,
        upload_through_64k_window_capped_at_128k
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    [{cert, Cert}, {key, Key} | Config].

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Stopped at 65536 bytes.
response_through_64k_window_capped_at_128k(Config) ->
    download(Config, 65536, 131072, ?MIB).

%% Stopped at 131072 bytes.
response_through_128k_window_capped_at_256k(Config) ->
    download(Config, 131072, 262144, ?MIB).

%% Stopped at 100000 bytes, and the server's send queue filled behind it.
response_larger_than_the_send_queue_through_200k_window(Config) ->
    download(Config, 100000, 200000, 64 * ?MIB).

%% Completed before too; the fence for the cases above.
response_through_1m_window_capped_at_2m(Config) ->
    download(Config, ?MIB, 2 * ?MIB, 32 * ?MIB).

%% The other direction: the server receives on a stream the client
%% opened, within its `max_stream_data_bidi_remote'.
upload_through_64k_window_capped_at_128k(Config) ->
    ServerQuic = #{
        max_data => 65536,
        max_stream_data_bidi_remote => 65536,
        max_receive_window => 131072
    },
    with_server(Config, ServerQuic, fun(Port) ->
        Conn = connect(Port, #{}),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/count">>), #{end_stream => false}
        ),
        ok = send_body(Conn, StreamId, body(?MIB)),
        ?assertEqual({200, integer_to_binary(?MIB)}, response(Conn, StreamId)),
        ok = quic_h3:close(Conn)
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% The client asks for Size bytes with the given windows and checks
%% every byte arrives.
download(Config, InitialWindow, MaxWindow, Size) ->
    with_server(Config, #{}, fun(Port) ->
        Conn = connect(Port, #{
            max_data => InitialWindow,
            max_stream_data_bidi_local => InitialWindow,
            max_receive_window => MaxWindow
        }),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"GET">>, <<"/bytes/", (integer_to_binary(Size))/binary>>)
        ),
        {Status, Body} = response(Conn, StreamId),
        %% A stall shows as {stalled, BytesSoFar} rather than a size.
        ?assertEqual({200, Size}, {Status, received(Body)}),
        ?assert(Body =:= body(Size)),
        ok = quic_h3:close(Conn)
    end).

with_server(Config, QuicOpts, F) ->
    Name = list_to_atom("h3_window_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun handle/5,
        quic_opts => QuicOpts
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(Port)
    after
        quic_h3:stop_server(Name)
    end.

handle(Conn, StreamId, <<"GET">>, <<"/bytes/", Size/binary>>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    send_body(Conn, StreamId, body(binary_to_integer(Size)));
handle(Conn, StreamId, <<"POST">>, <<"/count">>, _Headers) ->
    Buffered =
        case quic_h3:set_stream_handler(Conn, StreamId, self()) of
            ok -> [];
            {ok, Chunks} -> Chunks
        end,
    Size = count(Conn, StreamId, Buffered),
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, integer_to_binary(Size), true).

%% In pieces, retrying a refused piece as the HTTP/3 guide shows.
send_body(Conn, StreamId, Body) when byte_size(Body) =< ?PIECE ->
    send(Conn, StreamId, Body, true);
send_body(Conn, StreamId, Body) ->
    <<Piece:?PIECE/binary, Rest/binary>> = Body,
    ok = send(Conn, StreamId, Piece, false),
    send_body(Conn, StreamId, Rest).

send(Conn, StreamId, Data, Fin) ->
    case quic_h3:send_data(Conn, StreamId, Data, Fin) of
        {error, send_queue_full} ->
            timer:sleep(10),
            send(Conn, StreamId, Data, Fin);
        Result ->
            Result
    end.

count(Conn, StreamId, Buffered) ->
    Size = iolist_size([D || {D, _} <- Buffered]),
    case lists:any(fun({_, Fin}) -> Fin end, Buffered) of
        true -> Size;
        false -> count_rest(Conn, StreamId, Size)
    end.

count_rest(Conn, StreamId, Size) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            Size + byte_size(Data);
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            count_rest(Conn, StreamId, Size + byte_size(Data))
    after ?WAIT_MS -> {stalled, Size}
    end.

received(Body) when is_binary(Body) -> byte_size(Body);
received(Other) -> Other.

connect(Port, QuicOpts) ->
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{
        verify => false, sync => true, quic_opts => QuicOpts
    }),
    Conn.

headers(Method, Path) ->
    [
        {<<":method">>, Method},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, Path},
        {<<":authority">>, <<"localhost">>}
    ].

response(Conn, StreamId) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, _}} -> {Status, body(Conn, StreamId, [])};
        {quic_h3, Conn, {stream_reset, StreamId, _} = Reset} -> Reset
    after ?WAIT_MS -> no_response
    end.

body(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} -> iolist_to_binary([Acc, Data]);
        {quic_h3, Conn, {data, StreamId, Data, false}} -> body(Conn, StreamId, [Acc, Data]);
        {quic_h3, Conn, {stream_reset, StreamId, _} = Reset} -> Reset
    after ?WAIT_MS -> {stalled, iolist_size(Acc)}
    end.

%% The same bytes on both sides, repeating with a prime period so that a
%% piece dropped or reordered shows up.
body(Size) ->
    Block = <<<<((I * 7) rem 256)>> || I <- lists:seq(1, 4093)>>,
    Whole = binary:copy(Block, Size div 4093 + 1),
    binary:part(Whole, 0, Size).
