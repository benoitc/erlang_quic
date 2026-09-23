%%% -*- erlang -*-
%%%
%%% A response that carries a Content-Length but no body.
%%%
%%% RFC 9110 Section 8.6: the Content-Length on a response to HEAD states
%%% what the body would have been for a GET, and the response carries
%%% none. Section 6.4.1 says the same of 204 and 304. Reading that as a
%%% short body and resetting the stream with H3_MESSAGE_ERROR turns an
%%% ordinary HEAD into a failure.
%%%
%%% Server and client run in this VM over 127.0.0.1, the way hackney
%%% drives quic_h3, because the external servers the e2e suite talks to
%%% do not all put a Content-Length on a HEAD response, which is what
%%% let this through.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_no_content_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    head_with_content_length/1,
    no_content_statuses_with_content_length/1,
    a_genuinely_short_body_is_still_refused/1,
    a_caller_supplied_status_is_not_duplicated/1
]).

-define(WAIT_MS, 3000).

%% The body a GET on /doc would return, and the Content-Length every
%% response below announces.
-define(DOC, <<"0123456789012345678901234567890123456789">>).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        head_with_content_length,
        no_content_statuses_with_content_length,
        a_genuinely_short_body_is_still_refused,
        a_caller_supplied_status_is_not_duplicated
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

%% The shape hackney hit: HEAD answered with the Content-Length a GET
%% would have had and an empty body.
head_with_content_length(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"HEAD">>, <<"/doc">>)),
        {response, StreamId, 200, RespHeaders} = next(Conn),
        %% One :status, not two. The server adds it and must not also
        %% pass through one the decoder already produced.
        ?assertEqual(
            1, length([V || {<<":status">>, V} <- RespHeaders])
        ),
        ?assertEqual({data, StreamId, <<>>, true}, next(Conn)),
        %% and the connection is still good for the next request
        {ok, Next} = quic_h3:request(Conn, headers(<<"GET">>, <<"/doc">>)),
        ?assertMatch({response, Next, 200, _}, next(Conn)),
        ?assertEqual({data, Next, ?DOC, true}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% 204 and 304 never carry content either, whatever they announce.
no_content_statuses_with_content_length(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        lists:foreach(
            fun(Path) ->
                {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, Path)),
                ?assertMatch({response, StreamId, _, _}, next(Conn)),
                ?assertEqual({data, StreamId, <<>>, true}, next(Conn))
            end,
            [<<"/204">>, <<"/304">>]
        ),
        quic_h3:close(Conn)
    end).

%% The check still does its job: a GET whose body really is shorter than
%% the Content-Length is a stream error.
a_genuinely_short_body_is_still_refused(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/short">>)),
        ?assertMatch({response, StreamId, 200, _}, next(Conn)),
        ?assertMatch({stream_reset, StreamId, _}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% send_response/4 takes the status as an argument, so a `:status' in the
%% header list is the same header twice, and two of one pseudo-header is
%% a malformed response.
a_caller_supplied_status_is_not_duplicated(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/dup-status">>)),
        {response, StreamId, 200, RespHeaders} = next(Conn),
        ?assertEqual(1, length([V || {<<":status">>, V} <- RespHeaders])),
        quic_h3:close(Conn)
    end).

%%====================================================================
%% Server
%%====================================================================

with_server(Config, F) ->
    Name = list_to_atom("h3_no_content_" ++ integer_to_list(erlang:unique_integer([positive]))),
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

%% Every response announces the same Content-Length; what differs is
%% whether a body follows it.
handle(Conn, StreamId, <<"HEAD">>, <<"/doc">>, _Headers) ->
    respond(Conn, StreamId, 200, <<>>);
handle(Conn, StreamId, _Method, <<"/doc">>, _Headers) ->
    respond(Conn, StreamId, 200, ?DOC);
handle(Conn, StreamId, _Method, <<"/204">>, _Headers) ->
    respond(Conn, StreamId, 204, <<>>);
handle(Conn, StreamId, _Method, <<"/304">>, _Headers) ->
    respond(Conn, StreamId, 304, <<>>);
handle(Conn, StreamId, _Method, <<"/dup-status">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, [
        {<<":status">>, <<"200">>}, {<<"content-type">>, <<"text/plain">>}
    ]),
    ok = quic_h3:send_data(Conn, StreamId, <<>>, true);
handle(Conn, StreamId, _Method, <<"/short">>, _Headers) ->
    respond(Conn, StreamId, 200, <<"short">>);
handle(Conn, StreamId, _Method, _Path, _Headers) ->
    respond(Conn, StreamId, 404, <<>>).

respond(Conn, StreamId, Status, Body) ->
    Headers = [
        {<<"content-type">>, <<"text/plain">>},
        {<<"content-length">>, integer_to_binary(byte_size(?DOC))}
    ],
    ok = quic_h3:send_response(Conn, StreamId, Status, Headers),
    ok = quic_h3:send_data(Conn, StreamId, Body, true).

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

%% The next stream event the client connection reports.
next(Conn) ->
    receive
        {quic_h3, Conn, {settings, _}} -> next(Conn);
        {quic_h3, Conn, {goaway, _}} -> next(Conn);
        {quic_h3, Conn, {session_ticket, _}} -> next(Conn);
        {quic_h3, Conn, {early_data_rejected, _}} -> next(Conn);
        {quic_h3, Conn, Event} -> Event
    after ?WAIT_MS -> heard_nothing
    end.
