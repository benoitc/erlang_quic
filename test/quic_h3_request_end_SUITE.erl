%%% -*- erlang -*-
%%%
%%% A server handler reading a request body has to learn where it ends.
%%%
%%% The body ends with the stream, and the FIN can ride on the last frame
%%% of any kind: on the HEADERS of a request without a body (curl sends
%%% every GET that way), on the trailers, or in a bare STREAM frame. The
%%% handler registered with set_stream_handler/4 hears it as an empty
%%% fin-marked delivery, buffered until it registers.
%%%
%%% The server may also answer before the request is complete and then
%%% stop reading it (RFC 9114 Section 4.1.1). The client's RESET_STREAM
%%% that follows must not make the server abandon its response.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_request_end_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    headers_with_fin_end_the_body/1,
    trailers_end_the_body/1,
    bare_fin_ends_the_body/1,
    early_response_survives_stop_sending/1
]).

%% H3_NO_ERROR (RFC 9114 Section 8.1).
-define(NO_ERROR, 16#0100).

-define(WAIT_MS, 3000).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        headers_with_fin_end_the_body,
        trailers_end_the_body,
        bare_fin_ends_the_body,
        early_response_survives_stop_sending
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

%% HEADERS and FIN in one STREAM frame, the way curl sends a GET.
headers_with_fin_end_the_body(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"GET">>, <<"/read">>), #{end_stream => true}
        ),
        ?assertEqual({handler, {body, <<>>}}, await(handler)),
        ?assertMatch({response, StreamId, 200, _}, next(Conn)),
        ?assertEqual({data, StreamId, <<>>, true}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% A body followed by trailers carrying the FIN.
trailers_end_the_body(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/read">>), #{end_stream => false}
        ),
        ok = quic_h3:send_data(Conn, StreamId, <<"body">>, false),
        ok = quic_h3:send_trailers(Conn, StreamId, [{<<"x-checksum">>, <<"1">>}]),
        ?assertEqual({handler, {body, <<"body">>}}, await(handler)),
        ?assertMatch({response, StreamId, 200, _}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% The FIN alone, after the body, still reaches the handler.
bare_fin_ends_the_body(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/read">>), #{end_stream => false}
        ),
        ok = quic_h3:send_data(Conn, StreamId, <<"body">>, false),
        ok = quic:send_data(quic_h3:get_quic_conn(Conn), StreamId, <<>>, true),
        ?assertEqual({handler, {body, <<"body">>}}, await(handler)),
        ?assertMatch({response, StreamId, 200, _}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% The server answers a request still being sent, then stops reading it.
%% The client gets the whole response, and the server does not reset the
%% stream when the client's RESET_STREAM comes back. Loopback delivers
%% the response before any reset could catch it, so what is checked is
%% that the server never sent one.
early_response_survives_stop_sending(Config) ->
    with_server(Config, fun(Port) ->
        trace_resets(),
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/early">>), #{end_stream => false}
        ),
        Events = lists:sort([next(Conn), next(Conn), next(Conn)]),
        ?assertMatch(
            [
                {stop_sending, StreamId, ?NO_ERROR},
                {data, StreamId, <<"too large">>, true},
                {response, StreamId, 413, _}
            ],
            Events
        ),
        ?assertEqual(no_reset, await_reset(StreamId)),
        quic_h3:close(Conn)
    end).

%%====================================================================
%% Server
%%====================================================================

with_server(Config, F) ->
    Test = self(),
    Name = list_to_atom("h3_end_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun(C, S, M, P, H) -> handle(Test, C, S, M, P, H) end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(Port)
    after
        erlang:trace(all, false, [call]),
        erlang:trace_pattern({quic, reset_stream, 3}, false, [global]),
        quic_h3:stop_server(Name)
    end.

%% Registers once the request is dispatched, so the end of the body has
%% been buffered and is replayed as a message.
handle(Test, Conn, StreamId, _Method, <<"/read">>, _Headers) ->
    ok = quic_h3:set_stream_handler(Conn, StreamId, self(), #{drain_buffer => false}),
    Result = read_body(Conn, StreamId, <<>>),
    Test ! {handler, Result},
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, <<>>, true);
handle(_Test, Conn, StreamId, <<"POST">>, <<"/early">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 413, []),
    ok = quic_h3:send_data(Conn, StreamId, <<"too large">>, true),
    quic:stop_sending(quic_h3:get_quic_conn(Conn), StreamId, ?NO_ERROR).

read_body(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            read_body(Conn, StreamId, <<Acc/binary, Data/binary>>);
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            {body, <<Acc/binary, Data/binary>>}
    after ?WAIT_MS -> {no_end_of_body, Acc}
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

next(Conn) ->
    receive
        {quic_h3, Conn, {settings, _}} -> next(Conn);
        {quic_h3, Conn, {goaway, _}} -> next(Conn);
        {quic_h3, Conn, {session_ticket, _}} -> next(Conn);
        {quic_h3, Conn, Event} -> Event
    after ?WAIT_MS -> timeout
    end.

await(handler) ->
    receive
        {handler, _} = H -> H
    after ?WAIT_MS -> {handler, timeout}
    end.

trace_resets() ->
    erlang:trace_pattern({quic, reset_stream, 3}, true, [global]),
    erlang:trace(all, true, [call]).

%% The client answers the STOP_SENDING with its own RESET_STREAM; the
%% server must not answer that with one of its own.
await_reset(StreamId) ->
    receive
        {trace, _Pid, call, {quic, reset_stream, [_, StreamId, Code]}} -> {reset, Code}
    after 1000 -> no_reset
    end.
