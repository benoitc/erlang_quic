%%% -*- erlang -*-
%%%
%%% A peer that abandons an HTTP/3 request stream has to be heard.
%%%
%%% Either side can give up on a request: the server with RESET_STREAM
%%% part way through a response, the client with RESET_STREAM part way
%%% through a request body, or either with STOP_SENDING. The QUIC layer
%%% reports each to the HTTP/3 connection, which has to pass it on to
%%% whoever is waiting on that stream: the stream handler registered with
%%% set_stream_handler/3 if there is one, the connection owner otherwise.
%%% It used to drop them, so a client waiting on a response the server
%%% had reset waited out its own timeout.
%%%
%%% Server and client run in this VM over 127.0.0.1, the way hackney
%%% drives quic_h3.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_stream_reset_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    server_reset_after_partial_body/1,
    client_reset_reaches_server_handler/1,
    client_reset_reaches_owner_without_handler/1,
    stop_sending_reaches_the_handler/1
]).

%% H3_REQUEST_CANCELLED (RFC 9114 Section 8.1).
-define(REQUEST_CANCELLED, 16#010c).

%% Long enough for a loopback exchange, short enough that a dropped
%% reset shows as a failure of its own rather than as a timetrap.
-define(WAIT_MS, 3000).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        server_reset_after_partial_body,
        client_reset_reaches_server_handler,
        client_reset_reaches_owner_without_handler,
        stop_sending_reaches_the_handler
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

%% The shape hackney hit: HEADERS, part of the body, then a reset. The
%% client has to hear the reset with the server's code, and the
%% connection has to stay usable for the next request.
server_reset_after_partial_body(Config) ->
    with_server(Config, fun(Port, _Relay) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/partial">>)),
        ?assertMatch({response, StreamId, 200, _}, next(Conn)),
        ?assertEqual({data, StreamId, <<"partial">>, false}, next(Conn)),
        ?assertEqual({stream_reset, StreamId, ?REQUEST_CANCELLED}, next(Conn)),
        %% A fresh request on the same connection still completes.
        {ok, Next} = quic_h3:request(Conn, headers(<<"GET">>, <<"/ok">>)),
        ?assertMatch({response, Next, 200, _}, next(Conn)),
        ?assertEqual({data, Next, <<"ok">>, true}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% A server handler reading a request body registers for it, so the
%% client's reset has to reach it there.
client_reset_reaches_server_handler(Config) ->
    with_server(Config, fun(Port, _Relay) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/handler">>), #{end_stream => false}
        ),
        ok = quic_h3:send_data(Conn, StreamId, <<"part of a body">>, false),
        ?assertEqual({handler, registered}, await(handler)),
        ok = quic_h3:cancel(Conn, StreamId, ?REQUEST_CANCELLED),
        ?assertMatch({handler, {stream_reset, _, ?REQUEST_CANCELLED}}, await(handler)),
        quic_h3:close(Conn)
    end).

%% With no handler registered the connection owner hears it instead.
client_reset_reaches_owner_without_handler(Config) ->
    with_server(Config, fun(Port, _Relay) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/nohandler">>), #{end_stream => false}
        ),
        ok = quic_h3:send_data(Conn, StreamId, <<"part of a body">>, false),
        ?assertMatch(
            {server_owner, {request, _, <<"POST">>, <<"/nohandler">>, _}}, await(server_owner)
        ),
        ok = quic_h3:cancel(Conn, StreamId, ?REQUEST_CANCELLED),
        ?assertMatch({server_owner, {stream_reset, _, ?REQUEST_CANCELLED}}, await(server_owner)),
        quic_h3:close(Conn)
    end).

%% STOP_SENDING from the client reaches the handler writing the
%% response, and the server's transport answers it with a RESET_STREAM
%% carrying the same code, which the client owner hears.
stop_sending_reaches_the_handler(Config) ->
    with_server(Config, fun(Port, _Relay) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/stream">>)),
        ?assertMatch({response, StreamId, 200, _}, next(Conn)),
        ?assertEqual({data, StreamId, <<"chunk">>, false}, next(Conn)),
        ok = quic:stop_sending(quic_h3:get_quic_conn(Conn), StreamId, ?REQUEST_CANCELLED),
        ?assertMatch({handler, {stop_sending, _, ?REQUEST_CANCELLED}}, await(handler)),
        ?assertEqual({stream_reset, StreamId, ?REQUEST_CANCELLED}, next(Conn)),
        quic_h3:close(Conn)
    end).

%%====================================================================
%% Server
%%====================================================================

%% A server whose handler behaves per path, with a relay as each
%% connection's owner so server-side events reach the test process
%% tagged apart from the client's own.
with_server(Config, F) ->
    Test = self(),
    Relay = spawn_link(fun() -> relay(Test) end),
    Name = list_to_atom("h3_reset_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun(C, S, M, P, H) -> handle(Test, C, S, M, P, H) end,
        connection_handler => fun(_Conn) -> #{owner => Relay} end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(Port, Relay)
    after
        quic_h3:stop_server(Name),
        unlink(Relay),
        exit(Relay, kill)
    end.

handle(_Test, Conn, StreamId, <<"GET">>, <<"/partial">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    ok = quic_h3:send_data(Conn, StreamId, <<"partial">>, false),
    %% Let the body reach the client before the reset overtakes it.
    timer:sleep(100),
    quic_h3:cancel(Conn, StreamId, ?REQUEST_CANCELLED);
handle(_Test, Conn, StreamId, <<"GET">>, <<"/ok">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, <<"ok">>, true);
handle(Test, Conn, StreamId, <<"POST">>, <<"/handler">>, _Headers) ->
    register_as_handler(Conn, StreamId),
    Test ! {handler, registered},
    Test ! {handler, await_abort(Conn, StreamId)};
handle(_Test, _Conn, _StreamId, <<"POST">>, <<"/nohandler">>, _Headers) ->
    ok;
handle(Test, Conn, StreamId, <<"GET">>, <<"/stream">>, _Headers) ->
    register_as_handler(Conn, StreamId),
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    ok = quic_h3:send_data(Conn, StreamId, <<"chunk">>, false),
    Test ! {handler, await_abort(Conn, StreamId)}.

register_as_handler(Conn, StreamId) ->
    case quic_h3:set_stream_handler(Conn, StreamId, self()) of
        ok -> ok;
        {ok, _Buffered} -> ok
    end.

%% What the handler hears that ends its interest in the stream.
await_abort(Conn, StreamId) ->
    receive
        {quic_h3, Conn, {stream_reset, StreamId, _} = Reset} -> Reset;
        {quic_h3, Conn, {stop_sending, StreamId, _} = Stop} -> Stop;
        {quic_h3, Conn, {data, StreamId, _, _}} -> await_abort(Conn, StreamId)
    after ?WAIT_MS -> handler_heard_nothing
    end.

relay(Test) ->
    receive
        {quic_h3, _Conn, Event} -> Test ! {server_owner, Event};
        _ -> ok
    end,
    relay(Test).

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
        {quic_h3, Conn, Event} -> Event
    after ?WAIT_MS -> timeout
    end.

%% The next message from the server side, skipping owner events that
%% are not the one the case is waiting for.
await(handler) ->
    receive
        {handler, _} = H -> H
    after ?WAIT_MS -> {handler, timeout}
    end;
await(server_owner) ->
    receive
        {server_owner, {request, _, _, _, _}} = R -> R;
        {server_owner, {stream_reset, _, _}} = R -> R;
        {server_owner, {stop_sending, _, _}} = R -> R
    after ?WAIT_MS -> {server_owner, timeout}
    end.
