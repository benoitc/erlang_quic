%%% -*- erlang -*-
%%%
%%% Receive-side backpressure on HTTP/3 streams.
%%%
%%% With `flow_control => manual' the receiver grants credit only for the
%%% bytes the handler returns with quic_h3:consume/3, so a handler that
%%% stops reading stops the peer after about one stream window instead
%%% of filling its mailbox. The default, `auto', grants credit as data
%%% arrives.
%%%
%%% Server and client run in this VM over 127.0.0.1.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_manual_flow_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    an_upload_stops_while_the_handler_does_not_consume/1,
    consuming_lets_the_upload_complete/1,
    a_response_stops_while_the_client_does_not_consume/1,
    data_buffered_before_the_claim_is_consumed_like_any_other/1,
    auto_streams_are_unchanged/1,
    consume_on_a_finished_stream_is_an_error/1,
    consume_on_a_reset_stream_is_an_error/1,
    consume_on_an_auto_stream_is_a_no_op/1
]).

-define(KIB, 1024).
-define(MIB, (1024 * 1024)).
-define(WINDOW, (64 * ?KIB)).
-define(MAX_WINDOW, (128 * ?KIB)).
-define(UPLOAD, (4 * ?MIB)).
-define(PIECE, (16 * ?KIB)).
-define(PROBE, quic_h3_manual_flow_probe).
-define(WAIT_MS, 10000).
%% What a stalled transfer may still deliver: the manual window, plus what
%% the stream was granted before the handler claimed it. The transfer is
%% many times larger, so a receiver that keeps granting blows through it.
-define(STALL_BOUND, (?WINDOW + 2 * ?MAX_WINDOW)).

suite() ->
    [{timetrap, {seconds, 120}}].

all() ->
    [
        an_upload_stops_while_the_handler_does_not_consume,
        consuming_lets_the_upload_complete,
        a_response_stops_while_the_client_does_not_consume,
        data_buffered_before_the_claim_is_consumed_like_any_other,
        auto_streams_are_unchanged,
        consume_on_a_finished_stream_is_an_error,
        consume_on_a_reset_stream_is_an_error,
        consume_on_an_auto_stream_is_a_no_op
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    [{cert, Cert}, {key, Key} | Config].

end_per_suite(_Config) ->
    ok.

init_per_testcase(_Case, Config) ->
    true = register(?PROBE, self()),
    Config.

end_per_testcase(_Case, _Config) ->
    catch unregister(?PROBE),
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% The handler claims the stream in manual mode and consumes nothing: the
%% client's upload stops after about one window, then goes on to the end
%% once the handler consumes.
an_upload_stops_while_the_handler_does_not_consume(Config) ->
    with_server(Config, small_window(), fun(Port) ->
        Conn = connect(Port, #{}),
        {ok, StreamId} = upload(Conn, <<"/upload/held">>, body(?UPLOAD)),
        Handler = claimed(),
        Stalled = stalled_at(),
        ?assert(Stalled =< ?STALL_BOUND),
        Handler ! consume_from_now_on,
        ?assertEqual(
            {200, integer_to_binary(erlang:phash2(body(?UPLOAD)))}, response(Conn, StreamId)
        ),
        ok = quic_h3:close(Conn)
    end).

%% A handler that consumes each piece after reading it gets the whole
%% body, byte for byte.
consuming_lets_the_upload_complete(Config) ->
    with_server(Config, small_window(), fun(Port) ->
        Conn = connect(Port, #{}),
        {ok, StreamId} = upload(Conn, <<"/upload/consume">>, body(?UPLOAD)),
        ?assertEqual(
            {200, integer_to_binary(erlang:phash2(body(?UPLOAD)))}, response(Conn, StreamId)
        ),
        ok = quic_h3:close(Conn)
    end).

%% The client asks for a response in manual mode and does not consume:
%% the response stops within the client's window, then completes once the
%% client consumes what it has read.
a_response_stops_while_the_client_does_not_consume(Config) ->
    with_server(Config, #{}, fun(Port) ->
        Conn = connect(Port, small_window()),
        Size = ?UPLOAD,
        {ok, StreamId} = quic_h3:request(
            Conn,
            headers(<<"GET">>, <<"/bytes/", (integer_to_binary(Size))/binary>>),
            #{flow_control => manual}
        ),
        {200, Held} = held_response(Conn, StreamId),
        ?assert(byte_size(Held) =< ?WINDOW),
        ok = quic_h3:consume(Conn, StreamId, byte_size(Held)),
        Rest = consuming_body(Conn, StreamId, []),
        ?assert(<<Held/binary, Rest/binary>> =:= body(Size)),
        ok = quic_h3:close(Conn)
    end).

%% Body that arrived before the handler registered is handed over and
%% consumed like any other data: until it is, nothing more flows.
data_buffered_before_the_claim_is_consumed_like_any_other(Config) ->
    with_server(Config, small_window(), fun(Port) ->
        Conn = connect(Port, #{}),
        %% One window goes before the claim, the rest only after it.
        {ok, StreamId, Sender} = upload_after_go(
            Conn, <<"/upload/late">>, body(?UPLOAD), ?WINDOW
        ),
        Handler = claimed(),
        Buffered =
            receive
                {buffered, Bytes} -> Bytes
            after ?WAIT_MS -> ct:fail(no_buffered_report)
            end,
        ?assert(Buffered > 0),
        Sender ! go,
        Stalled = stalled_at(),
        ?assert(Stalled - Buffered =< ?STALL_BOUND),
        Handler ! consume_from_now_on,
        ?assertEqual(
            {200, integer_to_binary(erlang:phash2(body(?UPLOAD)))}, response(Conn, StreamId)
        ),
        ok = quic_h3:close(Conn)
    end).

%% Without the option the stream grants credit as data arrives, as before,
%% through the same small windows.
auto_streams_are_unchanged(Config) ->
    with_server(Config, small_window(), fun(Port) ->
        Conn = connect(Port, small_window()),
        {ok, Up} = upload(Conn, <<"/upload/auto">>, body(?UPLOAD)),
        ?assertEqual({200, integer_to_binary(erlang:phash2(body(?UPLOAD)))}, response(Conn, Up)),
        {ok, Down} = quic_h3:request(
            Conn, headers(<<"GET">>, <<"/bytes/", (integer_to_binary(?UPLOAD))/binary>>)
        ),
        {200, Body} = response(Conn, Down),
        ?assert(Body =:= body(?UPLOAD)),
        ok = quic_h3:close(Conn)
    end).

consume_on_a_finished_stream_is_an_error(Config) ->
    with_server(Config, #{}, fun(Port) ->
        Conn = connect(Port, #{}),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"GET">>, <<"/bytes/100">>), #{flow_control => manual}
        ),
        {200, Body} = response(Conn, StreamId),
        ?assertEqual(100, byte_size(Body)),
        ?assertEqual({error, unknown_stream}, quic_h3:consume(Conn, StreamId, 100)),
        ?assertMatch(#{}, quic_h3:get_settings(Conn)),
        ok = quic_h3:close(Conn)
    end).

consume_on_a_reset_stream_is_an_error(Config) ->
    with_server(Config, #{}, fun(Port) ->
        Conn = connect(Port, small_window()),
        {ok, StreamId} = quic_h3:request(
            Conn,
            headers(<<"GET">>, <<"/bytes/", (integer_to_binary(?UPLOAD))/binary>>),
            #{flow_control => manual}
        ),
        {200, _Held} = held_response(Conn, StreamId),
        ok = quic_h3:cancel(Conn, StreamId),
        ?assertMatch({error, _}, quic_h3:consume(Conn, StreamId, ?WINDOW)),
        ?assertMatch(#{}, quic_h3:get_settings(Conn)),
        ok = quic_h3:close(Conn)
    end).

consume_on_an_auto_stream_is_a_no_op(Config) ->
    with_server(Config, #{}, fun(Port) ->
        Conn = connect(Port, #{}),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"GET">>, <<"/bytes/", (integer_to_binary(?MIB))/binary>>)
        ),
        ?assertEqual(ok, quic_h3:consume(Conn, StreamId, 10)),
        {200, Body} = response(Conn, StreamId),
        ?assertEqual(?MIB, byte_size(Body)),
        ok = quic_h3:close(Conn)
    end).

%%====================================================================
%% Server
%%====================================================================

%% Windows small next to the transfers, so a stall is unmistakable.
small_window() ->
    #{
        max_data => ?WINDOW,
        max_stream_data_bidi_local => ?WINDOW,
        max_stream_data_bidi_remote => ?WINDOW,
        max_receive_window => ?MAX_WINDOW
    }.

with_server(Config, QuicOpts, F) ->
    Name = list_to_atom("h3_manual_" ++ integer_to_list(erlang:unique_integer([positive]))),
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
handle(Conn, StreamId, <<"POST">>, <<"/upload/auto">>, _Headers) ->
    Buffered = claim(Conn, StreamId, #{}),
    upload_loop(Conn, StreamId, auto, Buffered);
handle(Conn, StreamId, <<"POST">>, <<"/upload/consume">>, _Headers) ->
    Buffered = claim(Conn, StreamId, #{flow_control => manual}),
    ok = consume(Conn, StreamId, Buffered),
    upload_loop(Conn, StreamId, consume, Buffered);
handle(Conn, StreamId, <<"POST">>, <<"/upload/held">>, _Headers) ->
    Buffered = claim(Conn, StreamId, #{flow_control => manual}),
    ?PROBE ! {claimed, self()},
    ok = consume(Conn, StreamId, Buffered),
    upload_loop(Conn, StreamId, held, Buffered);
handle(Conn, StreamId, <<"POST">>, <<"/upload/late">>, _Headers) ->
    %% Let part of the body arrive and be buffered before claiming.
    timer:sleep(300),
    Buffered = claim(Conn, StreamId, #{flow_control => manual}),
    ?PROBE ! {claimed, self()},
    ?PROBE ! {buffered, iolist_size([D || {D, _} <- Buffered])},
    ?PROBE ! {got, iolist_size([D || {D, _} <- Buffered])},
    upload_loop(Conn, StreamId, held, Buffered).

claim(Conn, StreamId, Opts) ->
    case quic_h3:set_stream_handler(Conn, StreamId, self(), Opts#{drain_buffer => true}) of
        ok -> [];
        {ok, Chunks} -> Chunks
    end.

consume(Conn, StreamId, Chunks) ->
    case iolist_size([D || {D, _} <- Chunks]) of
        0 -> ok;
        N -> quic_h3:consume(Conn, StreamId, N)
    end.

%% Held: report each piece and consume nothing until told to, then
%% consume what was held and every later piece.
upload_loop(Conn, StreamId, Mode, Acc) ->
    case lists:any(fun({_, Fin}) -> Fin end, Acc) of
        true ->
            finish_upload(Conn, StreamId, Acc);
        false ->
            receive
                {quic_h3, Conn, {data, StreamId, Data, Fin}} ->
                    ?PROBE ! {got, byte_size(Data)},
                    ok = maybe_consume(Conn, StreamId, Mode, Data),
                    upload_loop(Conn, StreamId, Mode, Acc ++ [{Data, Fin}]);
                consume_from_now_on ->
                    ok = consume(Conn, StreamId, Acc),
                    upload_loop(Conn, StreamId, consume, Acc)
            after ?WAIT_MS * 3 -> exit(upload_timed_out)
            end
    end.

maybe_consume(Conn, StreamId, consume, Data) when byte_size(Data) > 0 ->
    quic_h3:consume(Conn, StreamId, byte_size(Data));
maybe_consume(_Conn, _StreamId, _Mode, _Data) ->
    ok.

finish_upload(Conn, StreamId, Acc) ->
    Body = iolist_to_binary([D || {D, _} <- Acc]),
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, integer_to_binary(erlang:phash2(Body)), true).

%%====================================================================
%% Helpers
%%====================================================================

%% The handler process, once it has claimed the stream.
claimed() ->
    receive
        {claimed, Handler} -> Handler
    after ?WAIT_MS -> ct:fail(not_claimed)
    end.

%% Bytes the handler has been given once no more arrive for a second.
stalled_at() ->
    stalled_at(0).

stalled_at(Got) ->
    receive
        {got, N} -> stalled_at(Got + N)
    after 1000 -> Got
    end.

upload(Conn, Path, Body) ->
    {ok, StreamId} = quic_h3:request(Conn, headers(<<"POST">>, Path), #{end_stream => false}),
    _ = spawn_link(fun() -> ok = send_body(Conn, StreamId, Body) end),
    {ok, StreamId}.

%% Send the first Head bytes, then the rest once the sender is told `go'.
upload_after_go(Conn, Path, Body, Head) ->
    {ok, StreamId} = quic_h3:request(Conn, headers(<<"POST">>, Path), #{end_stream => false}),
    <<First:Head/binary, Rest/binary>> = Body,
    Sender = spawn_link(fun() ->
        ok = send(Conn, StreamId, First, false),
        receive
            go -> ok = send_body(Conn, StreamId, Rest)
        end
    end),
    {ok, StreamId, Sender}.

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
        {quic_h3, Conn, {response, StreamId, Status, _}} -> {Status, body(Conn, StreamId, [])}
    after ?WAIT_MS -> no_response
    end.

body(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} -> iolist_to_binary([Acc, Data]);
        {quic_h3, Conn, {data, StreamId, Data, false}} -> body(Conn, StreamId, [Acc, Data])
    after ?WAIT_MS -> {stalled, iolist_size(Acc)}
    end.

%% The response status and what arrived before it stopped, without
%% consuming anything.
held_response(Conn, StreamId) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, _}} -> {Status, held(Conn, StreamId, [])}
    after ?WAIT_MS -> no_response
    end.

held(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, _Fin}} -> held(Conn, StreamId, [Acc, Data])
    after 1000 -> iolist_to_binary(Acc)
    end.

%% The rest of a manual response, consuming each piece as it is read.
consuming_body(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, Fin}} ->
            _ = quic_h3:consume(Conn, StreamId, byte_size(Data)),
            case Fin of
                true -> iolist_to_binary([Acc, Data]);
                false -> consuming_body(Conn, StreamId, [Acc, Data])
            end
    after ?WAIT_MS -> {stalled, iolist_size(Acc)}
    end.

%% The same bytes on both sides, repeating with a prime period so that a
%% piece dropped or reordered shows up.
body(Size) ->
    Block = <<<<((I * 7) rem 256)>> || I <- lists:seq(1, 4093)>>,
    Whole = binary:copy(Block, Size div 4093 + 1),
    binary:part(Whole, 0, Size).
