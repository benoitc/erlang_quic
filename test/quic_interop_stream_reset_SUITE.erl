%%% -*- erlang -*-
%%%
%%% Stream resets and STOP_SENDING against other QUIC stacks.
%%%
%%% quic_h3_stream_reset_SUITE runs both ends in this VM, so it cannot
%%% catch a misreading both ends share. These cases put aioquic and
%%% quic-go on the other side, started by docker/docker-compose.yml:
%%%
%%%   - the aioquic echo server (4433) reports every RESET_STREAM it
%%%     receives on a stream of its own, and sends STOP_SENDING when a
%%%     stream starts with "stop_sending <code>";
%%%   - the aioquic HTTP/3 server (4435) resets GET /reset?code=N after
%%%     part of the body, sends STOP_SENDING on POST /stop?code=N, and
%%%     lists the resets it received on GET /resets;
%%%   - the quic-go HTTP/3 example (4434) serves GET /N as N bytes, written
%%%     as one DATA frame.
%%%
%%% Each group skips when its server is not reachable. Hosts and ports
%%% come from QUIC_AIOQUIC_HOST, QUIC_AIOQUIC_PORT, QUIC_AIOQUIC_H3_PORT,
%%% QUIC_QUICGO_HOST and QUIC_QUICGO_PORT.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_interop_stream_reset_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_group/2, end_per_group/2]).
-export([
    reset_stream_reaches_aioquic/1,
    aioquic_answers_stop_sending/1,
    stop_sending_from_aioquic_is_answered/1,
    h3_reset_from_aioquic_after_partial_body/1,
    h3_stop_sending_from_aioquic_is_answered/1,
    h3_large_response_from_quic_go/1,
    h3_quic_go_answers_stop_sending/1
]).

%% H3_REQUEST_CANCELLED (RFC 9114 Section 8.1).
-define(REQUEST_CANCELLED, 16#010c).

-define(WAIT_MS, 5000).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [{group, aioquic}, {group, aioquic_h3}, {group, quic_go_h3}].

groups() ->
    [
        {aioquic, [sequence], [
            reset_stream_reaches_aioquic,
            aioquic_answers_stop_sending,
            stop_sending_from_aioquic_is_answered
        ]},
        {aioquic_h3, [sequence], [
            h3_reset_from_aioquic_after_partial_body,
            h3_stop_sending_from_aioquic_is_answered
        ]},
        {quic_go_h3, [sequence], [
            h3_large_response_from_quic_go,
            h3_quic_go_answers_stop_sending
        ]}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(aioquic, Config) ->
    peer(Config, "QUIC_AIOQUIC_HOST", "QUIC_AIOQUIC_PORT", 4433);
init_per_group(aioquic_h3, Config) ->
    peer(Config, "QUIC_AIOQUIC_HOST", "QUIC_AIOQUIC_H3_PORT", 4435);
init_per_group(quic_go_h3, Config) ->
    peer(Config, "QUIC_QUICGO_HOST", "QUIC_QUICGO_PORT", 4434).

end_per_group(_Group, _Config) ->
    ok.

peer(Config, HostVar, PortVar, DefaultPort) ->
    Host = os:getenv(HostVar, "127.0.0.1"),
    Port = list_to_integer(os:getenv(PortVar, integer_to_list(DefaultPort))),
    case quic_test_peer:reachable(Host, Port) of
        true -> [{host, Host}, {port, Port} | Config];
        false -> {skip, lists:flatten(io_lib:format("~s:~p not reachable", [Host, Port]))}
    end.

%%====================================================================
%% aioquic, raw QUIC
%%====================================================================

%% aioquic hears our RESET_STREAM with our code.
reset_stream_reaches_aioquic(Config) ->
    with_echo_stream(Config, fun(Conn, StreamId) ->
        ok = quic:reset_stream(Conn, StreamId, ?REQUEST_CANCELLED),
        ?assertEqual({StreamId, ?REQUEST_CANCELLED}, await_report(Conn))
    end).

%% We hear aioquic's RESET_STREAM answering our STOP_SENDING. RFC 9000
%% Section 3.5 only says it SHOULD carry our code, so the code is logged.
aioquic_answers_stop_sending(Config) ->
    with_echo_stream(Config, fun(Conn, StreamId) ->
        ok = quic:stop_sending(Conn, StreamId, ?REQUEST_CANCELLED),
        {stream_reset, StreamId, Code} = await_quic(Conn, stream_reset),
        {comment, io_lib:format("aioquic reset with code ~p", [Code])}
    end).

%% aioquic sends STOP_SENDING; we report it and answer with RESET_STREAM
%% carrying the same code, which aioquic hears.
stop_sending_from_aioquic_is_answered(Config) ->
    Conn = connect_echo(Config),
    try
        {ok, StreamId} = quic:open_stream(Conn),
        Ask = iolist_to_binary(["stop_sending ", integer_to_list(?REQUEST_CANCELLED)]),
        ok = quic:send_data(Conn, StreamId, Ask, false),
        ?assertEqual(
            {stop_sending, StreamId, ?REQUEST_CANCELLED}, await_quic(Conn, stop_sending)
        ),
        ?assertEqual({StreamId, ?REQUEST_CANCELLED}, await_report(Conn))
    after
        quic:close(Conn, normal)
    end.

%%====================================================================
%% aioquic, HTTP/3
%%====================================================================

%% The shape hackney hit, with aioquic as the server.
h3_reset_from_aioquic_after_partial_body(Config) ->
    Conn = connect_h3(Config),
    try
        Path = iolist_to_binary(["/reset?code=", integer_to_list(?REQUEST_CANCELLED)]),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, Path)),
        ?assertMatch({response, StreamId, 200, _}, next_h3(Conn)),
        ?assertEqual({data, StreamId, <<"partial">>, false}, next_h3(Conn)),
        ?assertEqual({stream_reset, StreamId, ?REQUEST_CANCELLED}, next_h3(Conn)),
        %% The connection still serves a new request.
        ?assertMatch({200, _}, http_get(Conn, <<"/resets">>))
    after
        quic_h3:close(Conn)
    end.

%% aioquic sends STOP_SENDING on our request body; the owner hears it,
%% and aioquic records the RESET_STREAM our transport answered with.
h3_stop_sending_from_aioquic_is_answered(Config) ->
    Conn = connect_h3(Config),
    try
        Path = iolist_to_binary(["/stop?code=", integer_to_list(?REQUEST_CANCELLED)]),
        {ok, StreamId} = quic_h3:request(
            Conn, headers(<<"POST">>, Path), #{end_stream => false}
        ),
        ?assertEqual({stop_sending, StreamId, ?REQUEST_CANCELLED}, next_h3(Conn)),
        {200, Resets} = http_get(Conn, <<"/resets">>),
        Line = iolist_to_binary([
            integer_to_list(StreamId), " ", integer_to_list(?REQUEST_CANCELLED), "\n"
        ]),
        ?assertNotEqual(nomatch, binary:match(Resets, Line))
    after
        quic_h3:close(Conn)
    end.

%%====================================================================
%% quic-go, HTTP/3
%%====================================================================

%% quic-go writes the whole body as one DATA frame, far past the 1 MiB a
%% buffered frame may have.
h3_large_response_from_quic_go(Config) ->
    Conn = connect_h3(Config),
    try
        ?assertMatch({200, <<_:20000000/binary>>}, http_get(Conn, <<"/20000000">>))
    after
        quic_h3:close(Conn)
    end.

%% STOP_SENDING part way through a large download: quic-go answers with
%% RESET_STREAM, which reaches the owner, and the connection stays usable.
h3_quic_go_answers_stop_sending(Config) ->
    Conn = connect_h3(Config),
    try
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/100000000">>)),
        ?assertMatch({response, StreamId, 200, _}, next_h3(Conn)),
        ?assertMatch({data, StreamId, _, false}, next_h3(Conn)),
        ok = quic:stop_sending(quic_h3:get_quic_conn(Conn), StreamId, ?REQUEST_CANCELLED),
        {stream_reset, StreamId, Code} = await_h3_reset(Conn, StreamId),
        ?assertMatch({200, <<_:10/binary>>}, http_get(Conn, <<"/10">>)),
        {comment, io_lib:format("quic-go reset with code ~p", [Code])}
    after
        quic_h3:close(Conn)
    end.

%%====================================================================
%% Helpers
%%====================================================================

connect_echo(Config) ->
    Opts = #{verify => false, alpn => [<<"echo">>]},
    {ok, Conn} = quic:connect(?config(host, Config), ?config(port, Config), Opts, self()),
    receive
        {quic, Conn, {connected, _}} -> Conn
    after ?WAIT_MS -> ct:fail(connect_timeout)
    end.

%% A stream whose first write has been echoed, neither side done.
with_echo_stream(Config, F) ->
    Conn = connect_echo(Config),
    try
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, <<"ping">>, false),
        ?assertMatch({stream_data, StreamId, <<"ping">>, false}, await_quic(Conn, stream_data)),
        F(Conn, StreamId)
    after
        quic:close(Conn, normal)
    end.

await_quic(Conn, Type) ->
    receive
        {quic, Conn, Event} when element(1, Event) =:= Type -> Event
    after ?WAIT_MS -> ct:fail({no_event, Type})
    end.

%% The echo server's "reset <stream> <code>" report.
await_report(Conn) ->
    receive
        {quic, Conn, {stream_data, _, <<"reset ", Report/binary>>, _}} ->
            [S, C] = binary:split(Report, <<" ">>),
            {binary_to_integer(S), binary_to_integer(C)}
    after ?WAIT_MS -> ct:fail(no_reset_report)
    end.

connect_h3(Config) ->
    {ok, Conn} = quic_h3:connect(
        ?config(host, Config), ?config(port, Config), #{verify => false, sync => true}
    ),
    Conn.

headers(Method, Path) ->
    [
        {<<":method">>, Method},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, Path},
        {<<":authority">>, <<"localhost">>}
    ].

next_h3(Conn) ->
    receive
        {quic_h3, Conn, {settings, _}} -> next_h3(Conn);
        {quic_h3, Conn, {goaway, _}} -> next_h3(Conn);
        {quic_h3, Conn, {session_ticket, _}} -> next_h3(Conn);
        {quic_h3, Conn, Event} -> Event
    after ?WAIT_MS -> timeout
    end.

%% Skips the body still in flight when the reset arrives.
await_h3_reset(Conn, StreamId) ->
    case next_h3(Conn) of
        {data, StreamId, _, _} -> await_h3_reset(Conn, StreamId);
        Event -> Event
    end.

%% A complete GET, as {Status, Body}.
http_get(Conn, Path) ->
    {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, Path)),
    {response, StreamId, Status, _} = next_h3(Conn),
    {Status, read_body(Conn, StreamId, <<>>)}.

read_body(Conn, StreamId, Acc) ->
    case next_h3(Conn) of
        {data, StreamId, Data, true} -> <<Acc/binary, Data/binary>>;
        {data, StreamId, Data, false} -> read_body(Conn, StreamId, <<Acc/binary, Data/binary>>);
        Other -> ct:fail({unexpected, Other})
    end.
