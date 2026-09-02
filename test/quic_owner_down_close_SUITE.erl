%%% -*- erlang -*-
%%%
%%% A dying connection owner must not leave the peer with a phantom
%%% connection.
%%%
%%% When a connection's owner process dies, the connection terminates
%%% with {shutdown, owner_down} and terminate/3 sends CONNECTION_CLOSE.
%%% The peer must learn about it promptly: without the close frame the
%%% peer holds the connection open until its idle timeout (up to a
%%% minute of phantom liveness), which upstream applications see as a
%%% host that is still connected long after its stack tore the
%%% connection down.
%%%
%%% The client side of this is exactly how a controlling application
%%% closes connections by killing the process that opened them, so the
%%% window between owner death and peer awareness is production-visible
%%% connection-state lag.

-module(quic_owner_down_close_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([peer_learns_of_owner_death/1, peer_learns_of_clean_close/1]).

%% How quickly the peer must see the close. Generous against slow rigs,
%% far below any idle/disconnect timeout it would otherwise wait for.
-define(NOTICE_MS, 2000).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [peer_learns_of_clean_close, peer_learns_of_owner_death].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Fence: a clean quic:close/2 reaches the peer within the same budget,
%% so a failure of the case below is about owner death specifically.
peer_learns_of_clean_close(_Config) ->
    {SConn, _Owner, CConn} = connected_pair(),
    ok = quic:close(CConn, normal),
    assert_closed(SConn).

peer_learns_of_owner_death(_Config) ->
    {SConn, Owner, _CConn} = connected_pair(),
    exit(Owner, kill),
    assert_closed(SConn).

assert_closed(SConn) ->
    receive
        {quic, SConn, {closed, Reason}} ->
            ct:pal("peer saw close: ~p", [Reason])
    after ?NOTICE_MS ->
        ct:fail({peer_never_saw_close, within_ms, ?NOTICE_MS})
    end.

%%====================================================================
%% Harness
%%====================================================================

%% Server-side connections are owned by the test process, so peer-side
%% events land in our mailbox. The client connection is owned by a
%% disposable process we can kill.
connected_pair() ->
    Test = self(),
    {ok, Server} = quic_test_echo_server:start(#{
        connection_handler => fun(ConnPid, _ConnRef) ->
            ok = quic:set_owner_sync(ConnPid, Test),
            {ok, Test}
        end
    }),
    Port = maps:get(port, Server),
    Owner = spawn(fun() ->
        {ok, C} = quic:connect(
            <<"127.0.0.1">>, Port, #{verify => false, alpn => [<<"echo">>]}, self()
        ),
        receive
            {quic, C, {connected, _}} -> Test ! {client_conn, C}
        after 10000 -> Test ! client_connect_timeout
        end,
        receive
        after infinity -> ok
        end
    end),
    CConn =
        receive
            {client_conn, C0} -> C0;
            client_connect_timeout -> ct:fail("client connect timeout")
        after 12000 -> ct:fail("no client conn")
        end,
    SConn =
        receive
            {quic, SC, {connected, _}} -> SC
        after 10000 -> ct:fail("no server-side connected event")
        end,
    {SConn, Owner, CConn}.
