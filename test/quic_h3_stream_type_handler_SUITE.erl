%%% -*- erlang -*-
%%%
%%% Request streams keep working when a stream_type_handler is set on
%%% both sides, as every WebTransport client and server does. A known
%%% request stream used to be classified again on every chunk, which
%%% replaced its state and reset it with H3_FRAME_UNEXPECTED at the next
%%% DATA frame. Only a new stream the peer opens is offered to the
%%% handler.
%%%
%%% Server and client run in this VM over 127.0.0.1.
-module(quic_h3_stream_type_handler_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    server_data_after_200_reaches_the_client/1,
    client_data_after_the_response_reaches_the_server/1,
    chunked_response_body_arrives_whole/1,
    peer_stream_with_a_signal_is_still_claimed/1
]).

-define(WT_STREAM, 16#41).
-define(WAIT_MS, 3000).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        server_data_after_200_reaches_the_client,
        client_data_after_the_response_reaches_the_server,
        chunked_response_body_arrives_whole,
        peer_stream_with_a_signal_is_still_claimed
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

%% Capsules after the 2xx of a WebTransport CONNECT are DATA on the
%% request stream, sent one at a time.
server_data_after_200_reaches_the_client(Config) ->
    with_server(Config, fun(Conn) ->
        {ok, StreamId} = quic_h3:request(Conn, connect(<<"/chunks">>), #{end_stream => false}),
        ?assertEqual({response, StreamId, 200}, next(Conn)),
        ?assertEqual(
            [<<"one">>, <<"two">>, <<"three">>],
            [expect_data(Conn, StreamId) || _ <- lists:seq(1, 3)]
        ),
        ?assertEqual(timeout, next(Conn, 200))
    end).

client_data_after_the_response_reaches_the_server(Config) ->
    with_server(Config, fun(Conn) ->
        {ok, StreamId} = quic_h3:request(Conn, connect(<<"/collect">>), #{end_stream => false}),
        ?assertEqual({response, StreamId, 200}, next(Conn)),
        lists:foreach(
            fun(Chunk) ->
                ok = quic_h3:send_data(Conn, StreamId, Chunk, false),
                timer:sleep(50)
            end,
            [<<"a">>, <<"b">>, <<"c">>]
        ),
        ?assertEqual(
            [<<"a">>, <<"b">>, <<"c">>], [await({collected, '_'}) || _ <- lists:seq(1, 3)]
        )
    end).

chunked_response_body_arrives_whole(Config) ->
    with_server(Config, fun(Conn) ->
        {ok, StreamId} = quic_h3:request(Conn, get(<<"/body">>)),
        ?assertEqual({response, StreamId, 200}, next(Conn)),
        ?assertEqual(<<"part1part2part3">>, body(Conn, StreamId, <<>>))
    end).

%% A bidi stream the client opens with the WebTransport signal is still
%% claimed by the server's handler.
peer_stream_with_a_signal_is_still_claimed(Config) ->
    with_server(Config, fun(Conn) ->
        {ok, StreamId} = quic_h3:open_bidi_stream(Conn, ?WT_STREAM),
        %% The signal and payload go straight onto the QUIC stream.
        ok = quic:send_data(
            quic_h3:get_quic_conn(Conn), StreamId, <<16#40, ?WT_STREAM, 0, "hi">>, false
        ),
        ?assertEqual({stream_type_open, bidi, StreamId, ?WT_STREAM}, await({server_owner, '_'})),
        ?assertMatch(
            {stream_type_data, bidi, StreamId, <<0, "hi">>, false}, await({server_owner, '_'})
        )
    end).

%%====================================================================
%% Server
%%====================================================================

with_server(Config, F) ->
    Test = self(),
    Relay = spawn_link(fun() -> relay(Test) end),
    Name = list_to_atom("h3_sth_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        settings => #{enable_connect_protocol => 1},
        stream_type_handler => fun claim_wt_streams/3,
        handler => fun(C, S, M, P, _H) -> handle(Test, C, S, M, P) end,
        connection_handler => fun(_Conn) -> #{owner => Relay} end
    }),
    {ok, Port} = quic:get_server_port(Name),
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{
        verify => false,
        sync => true,
        settings => #{enable_connect_protocol => 1},
        stream_type_handler => fun claim_wt_streams/3
    }),
    try
        F(Conn)
    after
        quic_h3:close(Conn),
        quic_h3:stop_server(Name),
        unlink(Relay),
        exit(Relay, kill)
    end.

claim_wt_streams(bidi, _StreamId, ?WT_STREAM) -> claim;
claim_wt_streams(_Dir, _StreamId, _Type) -> ignore.

handle(_Test, Conn, StreamId, <<"CONNECT">>, <<"/chunks">>) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    lists:foreach(
        fun(Chunk) ->
            timer:sleep(50),
            ok = quic_h3:send_data(Conn, StreamId, Chunk, false)
        end,
        [<<"one">>, <<"two">>, <<"three">>]
    ),
    receive
    after ?WAIT_MS -> ok
    end;
handle(Test, Conn, StreamId, <<"CONNECT">>, <<"/collect">>) ->
    case quic_h3:set_stream_handler(Conn, StreamId, self()) of
        ok -> ok;
        {ok, _Buffered} -> ok
    end,
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    collect(Test, Conn, StreamId);
handle(_Test, Conn, StreamId, <<"GET">>, <<"/body">>) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, []),
    ok = quic_h3:send_data(Conn, StreamId, <<"part1">>, false),
    timer:sleep(50),
    ok = quic_h3:send_data(Conn, StreamId, <<"part2">>, false),
    timer:sleep(50),
    quic_h3:send_data(Conn, StreamId, <<"part3">>, true).

collect(Test, Conn, StreamId) ->
    receive
        {quic_h3, Conn, {data, StreamId, <<>>, _}} ->
            collect(Test, Conn, StreamId);
        {quic_h3, Conn, {data, StreamId, Data, _}} ->
            Test ! {collected, Data},
            collect(Test, Conn, StreamId);
        {quic_h3, Conn, {stream_reset, StreamId, Code}} ->
            Test ! {collected, {stream_reset, Code}}
    after ?WAIT_MS -> ok
    end.

relay(Test) ->
    receive
        {quic_h3, _Conn, {stream_type_open, _, _, _} = E} -> Test ! {server_owner, E};
        {quic_h3, _Conn, {stream_type_data, _, _, _, _} = E} -> Test ! {server_owner, E};
        _ -> ok
    end,
    relay(Test).

%%====================================================================
%% Client
%%====================================================================

connect(Path) ->
    [
        {<<":method">>, <<"CONNECT">>},
        {<<":protocol">>, <<"webtransport">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, Path}
    ].

get(Path) ->
    [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, Path}
    ].

%% The client's next stream event, the response headers reduced to the
%% status.
next(Conn) ->
    next(Conn, ?WAIT_MS).

next(Conn, Timeout) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, _}} -> {response, StreamId, Status};
        {quic_h3, Conn, {data, StreamId, Data, Fin}} -> {data, StreamId, Data, Fin};
        {quic_h3, Conn, {stream_reset, StreamId, Code}} -> {stream_reset, StreamId, Code}
    after Timeout -> timeout
    end.

expect_data(Conn, StreamId) ->
    case next(Conn) of
        {data, StreamId, <<>>, _} -> expect_data(Conn, StreamId);
        {data, StreamId, Data, _} -> Data;
        Other -> Other
    end.

body(Conn, StreamId, Acc) ->
    case next(Conn) of
        {data, StreamId, Data, true} -> <<Acc/binary, Data/binary>>;
        {data, StreamId, Data, false} -> body(Conn, StreamId, <<Acc/binary, Data/binary>>);
        Other -> Other
    end.

await({Tag, _}) ->
    receive
        {Tag, Event} -> Event
    after ?WAIT_MS -> {no, Tag}
    end.
