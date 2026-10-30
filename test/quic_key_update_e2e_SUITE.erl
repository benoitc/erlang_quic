%%% -*- erlang -*-
%%%
%%% Key updates started by both ends in turn (RFC 9001 Section 6): after
%%% the client's update, the server's must still be followed.

-module(quic_key_update_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([peer_update_after_own_update/1]).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [peer_update_after_own_update].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

peer_update_after_own_update(_Config) ->
    Test = self(),
    {ok, #{port := Port} = Server} = quic_test_echo_server:start(#{
        connection_handler => fun(ConnPid, _ConnRef) ->
            Echo = spawn_link(fun() -> echo(ConnPid) end),
            ok = quic:set_owner_sync(ConnPid, Echo),
            Test ! {server_conn, ConnPid},
            {ok, Echo}
        end
    }),
    try
        {ok, Conn} = quic:connect(
            <<"127.0.0.1">>, Port, #{verify => false, alpn => [<<"echo">>]}, self()
        ),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 -> ct:fail("connection timeout")
        end,
        SConn =
            receive
                {server_conn, S} -> S
            after 10000 -> ct:fail("no server connection")
            end,
        ok = roundtrip(Conn, <<"before">>),
        ok = quic_connection:key_update(Conn),
        ok = roundtrip(Conn, <<"client updated">>),
        ok = server_key_update(Conn, SConn, 20),
        ok = roundtrip(Conn, <<"server updated">>),
        ok = roundtrip(Conn, <<"after">>),
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

%% The server can only start its update once it has seen a packet that
%% confirms the client's, so it may need another exchange first.
server_key_update(_Conn, _SConn, 0) ->
    ct:fail(server_never_updated);
server_key_update(Conn, SConn, N) ->
    case quic_connection:key_update(SConn) of
        ok ->
            ok;
        {error, key_update_in_progress} ->
            ok = roundtrip(Conn, <<"ping">>),
            server_key_update(Conn, SConn, N - 1)
    end.

roundtrip(Conn, Payload) ->
    {ok, StreamId} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, StreamId, Payload, true),
    receive
        {quic, Conn, {stream_data, StreamId, Got, true}} ->
            ?assertEqual(Payload, Got),
            ok
    after 5000 ->
        ct:fail({no_echo, Payload})
    end.

echo(Conn) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            ok = quic:send_data(Conn, StreamId, Data, Fin),
            echo(Conn);
        {quic, Conn, {closed, _}} ->
            ok;
        _ ->
            echo(Conn)
    end.
