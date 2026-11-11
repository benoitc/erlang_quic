%%% -*- erlang -*-
%%%
%%% A handshake that hears nothing from the peer is abandoned after the
%%% idle timeout, or the disconnect timeout when the idle timeout is off.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_handshake_timeout_tests).

-include_lib("eunit/include/eunit.hrl").

-define(OPTS, #{idle_timeout => 0, disconnect_timeout => 1000}).
-define(IDLE_OPTS, #{idle_timeout => 5000, disconnect_timeout => 1000}).

%% One Initial the server cannot decrypt creates a connection that never
%% sends anything, so nothing is in flight to time out on.
server_abandons_unreadable_initial_test_() ->
    {timeout, 30, fun server_abandons_unreadable_initial/0}.

server_abandons_unreadable_initial() ->
    {ok, #{name := Name, port := Port} = Server} = quic_test_echo_server:start(?OPTS),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    try
        ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, unreadable_initial()),
        ?assertMatch([_], wait_connections(Name, fun(Conns) -> Conns =/= [] end)),
        ?assertEqual([], wait_connections(Name, fun(Conns) -> Conns =:= [] end))
    after
        gen_udp:close(Socket),
        quic_test_echo_server:stop(Server)
    end.

%% The server never answers: the client is told the connection closed.
client_abandons_silent_server_test_() ->
    {timeout, 30, fun client_abandons_silent_server/0}.

client_abandons_silent_server() ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, Silent} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Silent),
        {ok, Conn} = quic:connect({127, 0, 0, 1}, Port, ?OPTS#{verify => false}, self()),
        receive
            {quic, Conn, {closed, Reason}} -> ?assertEqual(disconnect_timeout, Reason)
        after 10000 -> ?assert(false)
        end
    after
        gen_udp:close(Silent)
    end.

%% With the idle timeout on, it bounds the handshake: a silent server is
%% given up on at the idle timeout, not the disconnect timeout.
client_waits_for_the_idle_timeout_test_() ->
    {timeout, 30, fun client_waits_for_the_idle_timeout/0}.

client_waits_for_the_idle_timeout() ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, Silent} = gen_udp:open(0, [binary, {active, false}]),
    try
        {ok, Port} = inet:port(Silent),
        Start = erlang:monotonic_time(millisecond),
        {ok, Conn} = quic:connect({127, 0, 0, 1}, Port, ?IDLE_OPTS#{verify => false}, self()),
        receive
            {quic, Conn, {closed, Reason}} ->
                ?assertEqual(idle_timeout, Reason),
                ?assert(erlang:monotonic_time(millisecond) - Start >= 4000)
        after 10000 -> ?assert(false)
        end
    after
        gen_udp:close(Silent)
    end.

server_waits_for_the_idle_timeout_test_() ->
    {timeout, 30, fun server_waits_for_the_idle_timeout/0}.

server_waits_for_the_idle_timeout() ->
    {ok, #{name := Name, port := Port} = Server} = quic_test_echo_server:start(?IDLE_OPTS),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    try
        ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, unreadable_initial()),
        ?assertMatch([_], wait_connections(Name, fun(Conns) -> Conns =/= [] end)),
        timer:sleep(3000),
        ?assertMatch({ok, [_]}, quic:get_server_connections(Name)),
        ?assertEqual([], wait_connections(Name, fun(Conns) -> Conns =:= [] end))
    after
        gen_udp:close(Socket),
        quic_test_echo_server:stop(Server)
    end.

%% Fence: once connected, a quiet connection is not given up on.
connected_and_quiet_stays_open_test_() ->
    {timeout, 30, fun connected_and_quiet_stays_open/0}.

connected_and_quiet_stays_open() ->
    {ok, #{port := Port} = Server} = quic_test_echo_server:start(?OPTS),
    try
        Opts = ?OPTS#{verify => false, alpn => [<<"echo">>]},
        {ok, Conn} = quic:connect({127, 0, 0, 1}, Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(not_connected)
        end,
        receive
            {quic, Conn, {closed, Reason}} -> ?assertEqual(still_open, Reason)
        after 3000 -> ok
        end,
        quic:close(Conn)
    after
        quic_test_echo_server:stop(Server)
    end.

%% A v1 Initial with 8-byte connection IDs, padded to 1200 bytes, whose
%% protected part is zeros.
unreadable_initial() ->
    <<16#C3, 1:32, 8, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0:((1200 - 23) * 8)>>.

wait_connections(Name, Done) ->
    wait_connections(Name, Done, erlang:monotonic_time(millisecond) + 8000).

wait_connections(Name, Done, Deadline) ->
    {ok, Listed} = quic:get_server_connections(Name),
    Conns = lists:usort(Listed),
    case Done(Conns) orelse erlang:monotonic_time(millisecond) > Deadline of
        true ->
            Conns;
        false ->
            timer:sleep(50),
            wait_connections(Name, Done, Deadline)
    end.
