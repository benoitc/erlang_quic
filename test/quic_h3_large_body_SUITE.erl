%%% -*- erlang -*-
%%%
%%% HTTP/3 bodies larger than one buffered frame.
%%%
%%% RFC 9114 puts no limit on the size of a DATA frame, and a sender may
%%% write a whole body as one: quic_h3:send_data/4 does, and so does the
%%% Go http3 server for each Write. A DATA frame's payload has to reach
%%% the receiver as it arrives, not be held until the frame is complete,
%%% and a client streaming a response has no body buffer to cap.
%%%
%%% Server and client run in this VM over 127.0.0.1.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_large_body_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    memory_does_not_grow_with_the_frame/1,
    response_in_one_large_data_frame/1,
    request_body_in_one_large_data_frame/1,
    response_over_16_mib_without_content_length/1
]).

%% Five times the 1 MiB a frame used to be allowed.
-define(LARGE, (5 * 1024 * 1024)).
%% Eight times, for the case that watches what the connection holds.
-define(HUGE, (8 * 1024 * 1024)).
%% What the HTTP/3 connection may hold while that body streams through
%% it. Buffering the frame whole would need all 8 MiB.
-define(MEMORY_BOUND, (2 * 1024 * 1024)).
%% Past the 16 MiB a body without Content-Length used to be allowed.
-define(UNBOUNDED, (20 * 1024 * 1024)).
-define(CHUNK, (1024 * 1024)).

-define(WAIT_MS, 10000).

suite() ->
    [{timetrap, {seconds, 120}}].

all() ->
    [
        memory_does_not_grow_with_the_frame,
        response_in_one_large_data_frame,
        request_body_in_one_large_data_frame,
        response_over_16_mib_without_content_length
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

%% A DATA frame's payload passes through the connection rather than
%% collecting in it, so what the connection holds does not grow with the
%% frame's length.
memory_does_not_grow_with_the_frame(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/huge">>)),
        {200, Body, Peak} = measured_response(Conn, StreamId),
        ct:pal("~p byte frame, connection held at most ~p bytes", [?HUGE, Peak]),
        ?assertEqual(?HUGE, byte_size(Body)),
        ?assert(Peak < ?MEMORY_BOUND),
        quic_h3:close(Conn)
    end).

%% The whole body in one send_data/4 call is one DATA frame. The client
%% receives all of it, and the connection serves the next request.
response_in_one_large_data_frame(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/large">>)),
        {200, Body} = response(Conn, StreamId),
        ?assertEqual(body(?LARGE), Body),
        {ok, Next} = quic_h3:request(Conn, headers(<<"GET">>, <<"/small">>)),
        ?assertEqual({200, <<"small">>}, response(Conn, Next)),
        quic_h3:close(Conn)
    end).

%% The same for an upload: the server handler receives the whole body.
request_body_in_one_large_data_frame(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/upload">>), #{end_stream => false}
        ),
        ok = quic_h3:send_data(Conn, StreamId, body(?LARGE), true),
        ?assertEqual(
            {200, integer_to_binary(erlang:phash2(body(?LARGE)))}, response(Conn, StreamId)
        ),
        quic_h3:close(Conn)
    end).

%% A response with no Content-Length streams to the client past 16 MiB;
%% nothing on the client side holds the body.
response_over_16_mib_without_content_length(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/unbounded">>)),
        {200, Body} = response(Conn, StreamId),
        ?assertEqual(?UNBOUNDED, byte_size(Body)),
        quic_h3:close(Conn)
    end).

%%====================================================================
%% Server
%%====================================================================

with_server(Config, F) ->
    Name = list_to_atom("h3_large_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun handle/5
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(Port)
    after
        quic_h3:stop_server(Name)
    end.

handle(Conn, StreamId, <<"GET">>, <<"/large">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, body(?LARGE), true);
handle(Conn, StreamId, <<"GET">>, <<"/huge">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, body(?HUGE), true);
handle(Conn, StreamId, <<"GET">>, <<"/small">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, <<"small">>, true);
handle(Conn, StreamId, <<"GET">>, <<"/unbounded">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    send_chunks(Conn, StreamId, ?UNBOUNDED);
handle(Conn, StreamId, <<"POST">>, <<"/upload">>, _Headers) ->
    Buffered =
        case quic_h3:set_stream_handler(Conn, StreamId, self()) of
            ok -> [];
            {ok, Chunks} -> Chunks
        end,
    Body = read_upload(Conn, StreamId, Buffered),
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, integer_to_binary(erlang:phash2(Body)), true).

send_chunks(Conn, StreamId, Left) when Left =< ?CHUNK ->
    send(Conn, StreamId, binary:copy(<<"u">>, Left), true);
send_chunks(Conn, StreamId, Left) ->
    ok = send(Conn, StreamId, binary:copy(<<"u">>, ?CHUNK), false),
    send_chunks(Conn, StreamId, Left - ?CHUNK).

%% The connection refuses more once its send queue is full; wait for it
%% to drain and try again.
send(Conn, StreamId, Data, Fin) ->
    case quic_h3:send_data(Conn, StreamId, Data, Fin) of
        {error, send_queue_full} ->
            timer:sleep(10),
            send(Conn, StreamId, Data, Fin);
        Result ->
            Result
    end.

%% The body as buffered before registration, then as it streams in.
read_upload(Conn, StreamId, Buffered) ->
    case lists:any(fun({_, Fin}) -> Fin end, Buffered) of
        true -> iolist_to_binary([D || {D, _} <- Buffered]);
        false -> read_upload_rest(Conn, StreamId, [D || {D, _} <- Buffered])
    end.

read_upload_rest(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            iolist_to_binary([Acc, Data]);
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            read_upload_rest(Conn, StreamId, [Acc, Data])
    after ?WAIT_MS -> <<"upload timed out">>
    end.

%%====================================================================
%% Client
%%====================================================================

connect(Port) ->
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{verify => false, sync => true}),
    Conn.

headers(Method, Path) ->
    [
        {<<":method">>, Method},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, Path},
        {<<":authority">>, <<"localhost">>}
    ].

%% {Status, Body, Peak} where Peak is the most the HTTP/3 connection
%% process held at any point while the body arrived: its own memory plus
%% the refc binaries it references, which is where a buffered body sits.
measured_response(Conn, StreamId) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, _}} ->
            {Body, Peak} = measured_body(Conn, StreamId, [], held(Conn)),
            {Status, Body, Peak}
    after ?WAIT_MS -> no_response
    end.

measured_body(Conn, StreamId, Acc, Peak) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            {iolist_to_binary([Acc, Data]), max(Peak, held(Conn))};
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            measured_body(Conn, StreamId, [Acc, Data], max(Peak, held(Conn)))
    after ?WAIT_MS -> {iolist_to_binary(Acc), Peak}
    end.

held(Conn) ->
    {memory, Memory} = process_info(Conn, memory),
    {binary, Bins} = process_info(Conn, binary),
    Memory + lists:sum([Size || {_Id, Size, _Refc} <- lists:ukeysort(1, Bins)]).

%% {Status, Body} of a complete response, or the event that ended it.
response(Conn, StreamId) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, _}} -> {Status, body(Conn, StreamId, [])};
        {quic_h3, Conn, {error, _} = Error} -> Error;
        {quic_h3, Conn, {stream_reset, StreamId, _} = Reset} -> Reset
    after ?WAIT_MS -> no_response
    end.

body(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} -> iolist_to_binary([Acc, Data]);
        {quic_h3, Conn, {data, StreamId, Data, false}} -> body(Conn, StreamId, [Acc, Data]);
        {quic_h3, Conn, {error, _} = Error} -> Error;
        {quic_h3, Conn, {stream_reset, StreamId, _} = Reset} -> Reset
    after ?WAIT_MS -> {body_stalled, iolist_size(Acc)}
    end.

%% The same bytes on both sides, repeating with a prime period so that a
%% piece reordered or dropped at any packet or chunk size shows up.
body(Size) ->
    Block = <<<<((I * 7) rem 256)>> || I <- lists:seq(1, 4093)>>,
    binary:part(binary:copy(Block, Size div 4093 + 1), 0, Size).
