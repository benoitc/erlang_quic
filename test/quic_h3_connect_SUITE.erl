%%% -*- erlang -*-
%%%
%%% HTTP/3 extended-CONNECT (RFC 9220) end-to-end tests.
%%%
%%% Regression coverage for the 1.4.1 break where the response-HEADERS
%%% coalescing buffer stranded a CONNECT tunnel's 200: the server replies
%%% 200 without ending the stream and then waits for the client's tunnel
%%% DATA, while the client waits for the 200 before sending DATA. The
%%% buffered 200 never flushed, deadlocking the tunnel.
%%%
%%% The suite runs its own in-process H3 server (via quic_test_h3_server
%%% with a CONNECT-aware handler and enable_connect_protocol => 1) and also
%%% guards the body-less response shapes that share the same buffering path.

-module(quic_h3_connect_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    suite/0,
    all/0,
    init_per_suite/1,
    end_per_suite/1
]).

%% Test cases
-export([
    extended_connect_tunnel_echo/1,
    head_response_empty_body/1,
    empty_body_response/1,
    headers_then_trailers_no_body/1
]).

%% Server request handler (invoked in a spawned process per request)
-export([handle/5]).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        extended_connect_tunnel_echo,
        head_response_empty_body,
        empty_body_response,
        headers_then_trailers_no_body
    ].

init_per_suite(Config) ->
    {ok, Server} = quic_test_h3_server:start(#{
        handler => fun ?MODULE:handle/5,
        settings => #{enable_connect_protocol => 1}
    }),
    Host = "127.0.0.1",
    Port = maps:get(port, Server),
    ct:pal("H3 CONNECT server: ~s:~p", [Host, Port]),
    [{h3_host, Host}, {h3_port, Port}, {h3_server, Server} | Config].

end_per_suite(Config) ->
    case ?config(h3_server, Config) of
        undefined -> ok;
        Server -> quic_test_h3_server:stop(Server)
    end,
    ok.

%%====================================================================
%% Test cases
%%====================================================================

%% Extended CONNECT: client opens a CONNECT-with-:protocol stream without
%% ending it, the server replies 200 and the two exchange DATA both ways
%% with the stream staying open. On 1.4.1 the 200 is buffered and never
%% arrives, so this times out; with the fix it passes.
extended_connect_tunnel_echo(Config) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),

    {ok, Conn} = quic_h3:connect(Host, Port, #{
        verify => false,
        sync => true,
        settings => #{enable_connect_protocol => 1}
    }),

    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"webtransport">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, list_to_binary(Host)},
        {<<":path">>, <<"/wt">>}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers, #{end_stream => false}),

    %% The tunnel-open 200 must arrive before any tunnel DATA.
    200 = expect_response(Conn, StreamId, 10000),

    %% DATA flows both ways and the stream stays open between exchanges.
    ok = quic_h3:send_data(Conn, StreamId, <<"ping">>, false),
    ?assertEqual(<<"ping">>, expect_data(Conn, StreamId, 10000)),
    ok = quic_h3:send_data(Conn, StreamId, <<"pong">>, false),
    ?assertEqual(<<"pong">>, expect_data(Conn, StreamId, 10000)),

    quic_h3:close(Conn).

%% HEAD response: headers, no body. The handler ends the stream with a
%% fin-only send_data, which must flush the buffered HEADERS.
head_response_empty_body(Config) ->
    {Status, _Headers, Body} =
        do_request(Config, [
            {<<":method">>, <<"HEAD">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/head">>}
        ]),
    ?assertEqual(200, Status),
    ?assertEqual(<<>>, Body).

%% Empty 200 body: same fin-only-send_data flush path as HEAD.
empty_body_response(Config) ->
    {Status, _Headers, Body} =
        do_request(Config, [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/empty">>}
        ]),
    ?assertEqual(200, Status),
    ?assertEqual(<<>>, Body).

%% Headers then trailers, no body: exercises the do_send_trailers flush of
%% any still-buffered HEADERS.
headers_then_trailers_no_body(Config) ->
    {Status, _Headers, Body} =
        do_request(Config, [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/trailers">>}
        ]),
    ?assertEqual(200, Status),
    ?assertEqual(<<>>, Body).

%%====================================================================
%% Server request handler
%%====================================================================

handle(Conn, StreamId, <<"CONNECT">>, _Path, _Headers) ->
    %% Register for tunnel DATA, handling both set_stream_handler shapes.
    Buffered =
        case quic_h3:set_stream_handler(Conn, StreamId, self()) of
            ok -> [];
            {ok, B} -> B
        end,
    %% Open the tunnel: the 200 MUST precede any tunnel DATA.
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    %% Echo data that arrived before we registered, then live data.
    case echo_buffered(Conn, StreamId, Buffered) of
        done -> ok;
        continue -> connect_echo_loop(Conn, StreamId)
    end;
handle(Conn, StreamId, <<"HEAD">>, _Path, _Headers) ->
    %% No content-length on HEAD: we send zero body bytes and a content-length
    %% would trip the receiver's body-size check.
    ok = quic_h3:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
    quic_h3:send_data(Conn, StreamId, <<>>, true);
handle(Conn, StreamId, <<"GET">>, <<"/empty">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_data(Conn, StreamId, <<>>, true);
handle(Conn, StreamId, <<"GET">>, <<"/trailers">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    quic_h3:send_trailers(Conn, StreamId, [{<<"x-trailer">>, <<"end">>}]);
handle(Conn, StreamId, _Method, _Path, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 404, []),
    quic_h3:send_data(Conn, StreamId, <<"Not Found">>, true).

echo_buffered(_Conn, _StreamId, []) ->
    continue;
echo_buffered(Conn, StreamId, [{Data, true} | _]) ->
    quic_h3:send_data(Conn, StreamId, Data, true),
    done;
echo_buffered(Conn, StreamId, [{Data, false} | Rest]) ->
    quic_h3:send_data(Conn, StreamId, Data, false),
    echo_buffered(Conn, StreamId, Rest).

connect_echo_loop(Conn, StreamId) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            quic_h3:send_data(Conn, StreamId, Data, true);
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            quic_h3:send_data(Conn, StreamId, Data, false),
            connect_echo_loop(Conn, StreamId);
        {quic_h3, Conn, {stream_end, StreamId}} ->
            ok
    after 30000 ->
        ok
    end.

%%====================================================================
%% Client helpers
%%====================================================================

do_request(Config, Headers0) ->
    Host = ?config(h3_host, Config),
    Port = ?config(h3_port, Config),
    {ok, Conn} = quic_h3:connect(Host, Port, #{verify => false, sync => true}),
    Headers = Headers0 ++ [{<<":authority">>, list_to_binary(Host)}],
    {ok, StreamId} = quic_h3:request(Conn, Headers),
    Result = receive_response(Conn, StreamId, 10000, undefined, [], <<>>),
    quic_h3:close(Conn),
    Result.

expect_response(Conn, StreamId, Timeout) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, _Headers}} -> Status;
        {quic_h3, Conn, {headers, StreamId, Status, _Headers}} -> Status
    after Timeout ->
        ct:fail({connect_response_timeout, StreamId})
    end.

expect_data(Conn, StreamId, Timeout) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, _Fin}} -> Data
    after Timeout ->
        ct:fail({connect_data_timeout, StreamId})
    end.

receive_response(Conn, StreamId, Timeout, Status, Headers, BodyAcc) ->
    receive
        {quic_h3, Conn, {response, StreamId, RespStatus, RespHeaders}} ->
            receive_response(Conn, StreamId, Timeout, RespStatus, RespHeaders, BodyAcc);
        {quic_h3, Conn, {headers, StreamId, RespStatus, RespHeaders}} ->
            receive_response(Conn, StreamId, Timeout, RespStatus, RespHeaders, BodyAcc);
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            {Status, Headers, <<BodyAcc/binary, Data/binary>>};
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            receive_response(
                Conn, StreamId, Timeout, Status, Headers, <<BodyAcc/binary, Data/binary>>
            );
        {quic_h3, Conn, {trailers, StreamId, _Trailers}} ->
            {Status, Headers, BodyAcc};
        {quic_h3, Conn, {stream_end, StreamId}} ->
            {Status, Headers, BodyAcc}
    after Timeout ->
        ct:fail({response_timeout, StreamId, Status, byte_size(BodyAcc)})
    end.
