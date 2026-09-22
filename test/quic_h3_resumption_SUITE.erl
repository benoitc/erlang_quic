%%% -*- erlang -*-
%%%
%%% Session resumption, chained.
%%%
%%% Tickets are single-use, so a client that resumes again needs the
%%% ticket its resumed connection issued.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_resumption_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("quic/include/quic.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([a_resumed_connection_issues_a_new_ticket/1]).

%% A loopback resumption takes a few milliseconds; this is far inside
%% the handshake's own probe timeouts, so a stall shows as a failure.
-define(ROUND_MS, 2000).

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [a_resumed_connection_issues_a_new_ticket].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, Server} = quic_test_h3_server:start(),
    [{server, Server} | Config].

end_per_suite(Config) ->
    quic_test_h3_server:stop(?config(server, Config)).

%%====================================================================
%% Cases
%%====================================================================

%% Tickets are single-use, so a client resumes again only with the ticket
%% its resumed connection issued.
a_resumed_connection_issues_a_new_ticket(Config) ->
    Port = port(Config),
    {ok, First} = connect(Port, #{}),
    {ok, Ticket} = request_and_ticket(First),
    quic_h3:close(First),
    {ok, Resumed} = connect(Port, #{session_ticket => Ticket}),
    Result = request_and_ticket(Resumed),
    quic_h3:close(Resumed),
    ?assertMatch({ok, #session_ticket{}}, Result).

%%====================================================================
%% Helpers
%%====================================================================

port(Config) ->
    maps:get(port, ?config(server, Config)).

connect(Port, QuicOpts) ->
    quic_h3:connect("127.0.0.1", Port, #{
        verify => false, sync => true, connect_timeout => ?ROUND_MS, quic_opts => QuicOpts
    }).

%% One GET answered in full, and the session ticket the connection issued.
request_and_ticket(Conn) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    Deadline = erlang:monotonic_time(millisecond) + ?ROUND_MS,
    case quic_h3:request(Conn, Headers) of
        {ok, StreamId} -> await(Conn, StreamId, Deadline, undefined, false);
        Error -> {request_failed, Error}
    end.

await(_Conn, _StreamId, _Deadline, Ticket, true) when Ticket =/= undefined ->
    {ok, Ticket};
await(Conn, StreamId, Deadline, Ticket, Done) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {quic_h3, Conn, {session_ticket, T}} -> await(Conn, StreamId, Deadline, T, Done);
        {quic_h3, Conn, {data, StreamId, _, true}} -> await(Conn, StreamId, Deadline, Ticket, true);
        {quic_h3, Conn, {stream_reset, StreamId, _} = Reset} -> Reset;
        {quic_h3, Conn, {error, _} = Error} -> Error
    after Left ->
        {stalled, #{response_done => Done, ticket => Ticket =/= undefined}}
    end.
