%%% -*- erlang -*-
%%%
%%% Streams below the GOAWAY identifier keep running after a GOAWAY.
%%%
%%% RFC 9114 Section 5.2 only stops new requests. Everything that acts on
%%% an existing stream has to keep working on both sides of the drain:
%%% the client resetting a request it no longer wants, the peer's resets
%%% reaching whoever waits on the stream, trailers and responses on
%%% in-flight requests, and the query calls that read connection state.
%%% The GOAWAY states used to drop all of these, so a cancel after GOAWAY
%%% sent nothing and a call after GOAWAY waited out its own timeout.
%%%
%%% Server and client run in this VM over 127.0.0.1.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_goaway_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    cancel_after_goaway_resets_the_stream/1,
    peer_reset_after_goaway_reaches_owner/1,
    trailers_after_goaway_reach_the_server/1,
    response_after_goaway_sent_reaches_client/1,
    calls_after_goaway_are_answered/1
]).

%% H3_REQUEST_CANCELLED (RFC 9114 Section 8.1).
-define(REQUEST_CANCELLED, 16#010c).

%% Long enough for a loopback exchange, short enough that a dropped
%% event shows as a failure of its own rather than as a timetrap.
-define(WAIT_MS, 3000).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        cancel_after_goaway_resets_the_stream,
        peer_reset_after_goaway_reaches_owner,
        trailers_after_goaway_reach_the_server,
        response_after_goaway_sent_reaches_client,
        calls_after_goaway_are_answered
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

%% The client gives up on a request after the server's GOAWAY: its
%% RESET_STREAM has to go out and reach the handler reading the body.
cancel_after_goaway_resets_the_stream(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/hold">>), #{end_stream => false}
        ),
        ok = quic_h3:send_data(Conn, StreamId, <<"part of a body">>, false),
        ?assertMatch({handler, {goaway_sent, _}}, await(handler)),
        ?assertMatch({goaway, _}, next(Conn)),
        ok = quic_h3:cancel(Conn, StreamId, ?REQUEST_CANCELLED),
        ?assertEqual({handler, {stream_reset, StreamId, ?REQUEST_CANCELLED}}, await(handler)),
        quic_h3:close(Conn)
    end).

%% The server resets an in-flight response after its GOAWAY: the client
%% owner has to hear the reset, not wait for a body that never comes.
peer_reset_after_goaway_reaches_owner(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/reset">>)),
        {handler, {goaway_sent, Handler}} = await(handler),
        %% The response travels on the request stream and the GOAWAY on
        %% the control stream, so the client may see them in either order.
        Events = [next(Conn), next(Conn), next(Conn)],
        ?assertMatch({response, StreamId, 200, _}, lists:keyfind(response, 1, Events)),
        ?assertMatch({data, StreamId, <<"partial">>, false}, lists:keyfind(data, 1, Events)),
        ?assertMatch({goaway, _}, lists:keyfind(goaway, 1, Events)),
        Handler ! go,
        ?assertEqual({stream_reset, StreamId, ?REQUEST_CANCELLED}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% Trailers end a request body that was already in flight when the
%% GOAWAY arrived; the server owner has to receive them.
trailers_after_goaway_reach_the_server(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/hold">>), #{end_stream => false}
        ),
        ok = quic_h3:send_data(Conn, StreamId, <<"part of a body">>, false),
        ?assertMatch({handler, {goaway_sent, _}}, await(handler)),
        ?assertMatch({goaway, _}, next(Conn)),
        Trailers = [{<<"x-checksum">>, <<"abc">>}],
        ?assertEqual(ok, quic_h3:send_trailers(Conn, StreamId, Trailers)),
        ?assertMatch({server_owner, {trailers, _, Trailers}}, await(server_owner)),
        quic_h3:close(Conn)
    end).

%% A server that has sent GOAWAY still answers the requests it accepted
%% before it.
response_after_goaway_sent_reaches_client(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/respond">>)),
        ?assertMatch({goaway, _}, next(Conn)),
        ?assertMatch({response, StreamId, 200, _}, next(Conn)),
        ?assertEqual({data, StreamId, <<"late">>, true}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% After GOAWAY every call is still answered: queries return what they
%% did before, and a call the connection does not know is refused
%% instead of left to time out.
calls_after_goaway_are_answered(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, <<"/hold">>), #{end_stream => false}
        ),
        ?assertMatch({handler, {goaway_sent, _}}, await(handler)),
        ?assertMatch({goaway, _}, next(Conn)),
        ?assert(is_pid(quic_h3:get_quic_conn(Conn))),
        ?assert(is_map(quic_h3:get_settings(Conn))),
        ?assert(is_map(quic_h3:get_peer_settings(Conn))),
        ?assertEqual(ok, quic_h3:set_stream_handler(Conn, StreamId, self())),
        ?assertEqual({error, unknown_call}, gen_statem:call(Conn, no_such_call, 1000)),
        quic_h3:close(Conn)
    end).

%%====================================================================
%% Server
%%====================================================================

%% A server whose handler sends GOAWAY on the connection it serves, with
%% a relay as each connection's owner so server-side events reach the
%% test process tagged apart from the client's own.
with_server(Config, F) ->
    Test = self(),
    Relay = spawn_link(fun() -> relay(Test) end),
    Name = list_to_atom("h3_goaway_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun(C, S, M, P, H) -> handle(Test, C, S, M, P, H) end,
        connection_handler => fun(_Conn) -> #{owner => Relay} end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(Port)
    after
        quic_h3:stop_server(Name),
        unlink(Relay),
        exit(Relay, kill)
    end.

%% Hold the request open across a GOAWAY and report how it ends.
handle(Test, Conn, StreamId, <<"POST">>, <<"/hold">>, _Headers) ->
    register_as_handler(Conn, StreamId),
    ok = quic_h3:goaway(Conn),
    Test ! {handler, {goaway_sent, self()}},
    Test ! {handler, await_abort(Conn, StreamId)};
%% Start a response, send GOAWAY, then reset once the test says the
%% client has seen the GOAWAY.
handle(Test, Conn, StreamId, <<"GET">>, <<"/reset">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    ok = quic_h3:send_data(Conn, StreamId, <<"partial">>, false),
    ok = quic_h3:goaway(Conn),
    Test ! {handler, {goaway_sent, self()}},
    receive
        go -> ok
    end,
    quic_h3:cancel(Conn, StreamId, ?REQUEST_CANCELLED);
%% Send GOAWAY first, then answer the request it was accepted before.
handle(_Test, Conn, StreamId, <<"GET">>, <<"/respond">>, _Headers) ->
    ok = quic_h3:goaway(Conn),
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, <<"late">>, true).

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

%% The next event the client connection reports, GOAWAY included.
next(Conn) ->
    receive
        {quic_h3, Conn, {settings, _}} -> next(Conn);
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
        {server_owner, {trailers, _, _}} = T -> T
    after ?WAIT_MS -> {server_owner, timeout}
    end.
