%%% -*- erlang -*-
%%%
%%% The frames a server sends on entering `connected' (queued data,
%%% NEW_TOKEN, the first PMTU probe) must leave with that transition,
%%% not with the next event on the connection.
%%%
%%% They go through the per-connection send batch, and the state-enter
%%% handler returned without flushing it, so they sat there until
%%% something else (an ACK, a timer) happened to flush. On a quiet
%%% connection that is the peer's delayed ACK or a PTO later; any
%%% consumer waiting for the token, and the MTU discovery, waited with
%%% them. This suite is a guard on the fixed behaviour: it holds with
%%% the fix, and the flake it was distilled from (the server-side
%%% baseline in quic_server_batching_SUITE seeing two packets built but
%%% not yet flushed) is what showed the bug.
-module(quic_post_handshake_flush_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([nothing_pending_after_connected/1]).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [nothing_pending_after_connected].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%% The client reaches the server through a bridge that can drop the
%% client-to-server direction. Once the handshake is complete the
%% bridge is blackholed, so nothing from the client can reach the
%% server and flush a batch on its behalf; the server must have flushed
%% everything it queued on entering `connected' by itself.
nothing_pending_after_connected(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{
        %% A token secret makes the server issue NEW_TOKEN on connect.
        reset_secret => crypto:strong_rand_bytes(32)
    }),
    Port = maps:get(port, Server),
    try
        {Conn, Bridge} = connect_through_bridge(Port),
        Bridge ! blackhole,
        SConn = server_connection(maps:get(name, Server)),
        ok = wait_connected(SConn, 400),
        {ok, Stats} = quic:get_stats(SConn),
        ct:pal("server stats right after connected: ~p", [Stats]),
        ?assertEqual(0, maps:get(send_batch_pending, Stats)),
        ?assert(maps:get(packets_sent, Stats) > 0),
        Bridge ! heal,
        ok = quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

server_connection(Name) ->
    {ok, Pids} = quic:get_server_connections(Name),
    [Pid | _] = lists:usort(Pids),
    Pid.

%% The server side becomes connected when the client's Finished is
%% processed; that datagram left before the client learned it was
%% connected, so it is through the bridge before the blackhole.
wait_connected(_Pid, 0) ->
    {error, server_never_connected};
wait_connected(Pid, N) ->
    case catch quic_connection:get_state(Pid) of
        {connected, _} ->
            ok;
        _ ->
            timer:sleep(5),
            wait_connected(Pid, N - 1)
    end.

%%====================================================================
%% Bridge harness (as in quic_stranded_window_recovery_SUITE)
%%====================================================================

connect_through_bridge(Port) ->
    ServerIP = {127, 0, 0, 1},
    SocketRef = make_ref(),
    Bridge = spawn_link(fun() -> bridge_init(ServerIP, Port, SocketRef) end),
    Adapter = #{
        send_fun => fun(IP, P, Pkt) ->
            Bridge ! {send, IP, P, Pkt},
            ok
        end,
        close_fun => fun() ->
            Bridge ! stop,
            ok
        end,
        local => {{127, 0, 0, 1}, 0},
        socket_ref => SocketRef
    },
    Opts = #{
        verify => false,
        alpn => [<<"echo">>],
        socket_backend => adapter,
        socket_adapter => Adapter,
        %% No immediate ACKs from the client: the server's post-handshake
        %% packets must not be flushed by an ACK racing the blackhole.
        ack_packet_tolerance => 1000
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    Bridge ! {set_conn, Conn},
    receive
        {quic, Conn, {connected, _}} -> {Conn, Bridge}
    after 10000 -> ct:fail("connect timeout")
    end.

bridge_init(ServerIP, ServerPort, SocketRef) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    bridge_loop(#{
        sock => Sock,
        conn => undefined,
        pending => [],
        blackhole => false,
        server => {ServerIP, ServerPort},
        socket_ref => SocketRef
    }).

bridge_loop(#{sock := Sock, server := {ServerIP, ServerPort}} = Bridge) ->
    receive
        {set_conn, Conn} ->
            [deliver(Bridge, Conn, D) || D <- lists:reverse(maps:get(pending, Bridge))],
            bridge_loop(Bridge#{conn := Conn, pending := []});
        blackhole ->
            bridge_loop(Bridge#{blackhole := true});
        heal ->
            bridge_loop(Bridge#{blackhole := false});
        {send, _IP, _Port, Pkt} ->
            case maps:get(blackhole, Bridge) of
                true -> ok;
                false -> ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt)
            end,
            bridge_loop(Bridge);
        {udp, Sock, _IP, _Port, Data} ->
            case maps:get(conn, Bridge) of
                undefined ->
                    bridge_loop(Bridge#{pending := [Data | maps:get(pending, Bridge)]});
                Conn ->
                    deliver(Bridge, Conn, Data),
                    bridge_loop(Bridge)
            end;
        stop ->
            gen_udp:close(Sock);
        _ ->
            bridge_loop(Bridge)
    end.

deliver(#{server := {ServerIP, ServerPort}, socket_ref := SocketRef}, Conn, Data) ->
    Conn ! {udp, SocketRef, ServerIP, ServerPort, Data}.
