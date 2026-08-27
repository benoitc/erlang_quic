%%% -*- erlang -*-
%%%
%%% Recovery after the server's first handshake flight is lost.
%%%
%%% Initial and Handshake packets are not loss-tracked, so a server
%%% whose ServerHello-to-Finished flight is dropped never resent it:
%%% once its TLS state has advanced, the client's Initial retransmits
%%% only elicit ACKs, and the handshake wedges until the connect
%%% timeout. The fix retains {ServerHello, Initial offset, Handshake
%%% payload} until the client's Finished arrives and replays the
%%% flight on the client Initial's backoff schedule.
%%%
%%% The harness drops everything the server sends for a fixed window
%%% covering the original flight and the first retransmit attempts,
%%% then heals the path. Without server-side retransmission there is
%%% nothing left to deliver after the heal, so the case fails on a
%%% connect timeout; with it the handshake completes on the first
%%% attempt after the window.
%%%
%%% The credit side of the same storm-failure class is pinned in
%%% quic_amp_batch_accounting_tests.
%%%
%%% The window (rather than a fixed drop count) keeps the case
%%% deterministic against client Initial retransmits: however many
%%% copies of the flight the client manages to elicit inside the
%%% window, they are all dropped.

-module(quic_server_flight_retransmit_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([control_plain_handshake/1, completes_after_the_first_flight_is_lost/1]).

%% Covers the original flight plus the first two replay attempts, so
%% recovery genuinely depends on the timer refiring after the heal.
-define(DROP_MS, 700).
%% Budget for the handshake once the path is back. Deliberately loose
%% so the case fails on a wedge rather than on a slow machine.
-define(CONNECT_MS, 20000).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [control_plain_handshake, completes_after_the_first_flight_is_lost].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Fence: the same handshake over the same harness with no drop window.
control_plain_handshake(_Config) ->
    with_server(fun(Port) ->
        {Conn, _Bridge} = connect_through_bridge(Port, 0),
        connected_within(Conn, ?CONNECT_MS),
        echo_roundtrip(Conn),
        quic:close(Conn, normal)
    end).

completes_after_the_first_flight_is_lost(_Config) ->
    with_server(fun(Port) ->
        Start = erlang:monotonic_time(millisecond),
        {Conn, _Bridge} = connect_through_bridge(Port, ?DROP_MS),
        connected_within(Conn, ?CONNECT_MS),
        Elapsed = erlang:monotonic_time(millisecond) - Start,
        ct:pal("handshake completed ~p ms after connect", [Elapsed]),
        %% The premise: completion required surviving the window. A
        %% handshake that finished inside it means the drop never
        %% engaged and the case is not testing the retransmit.
        ?assert(Elapsed >= ?DROP_MS),
        echo_roundtrip(Conn),
        quic:close(Conn, normal)
    end).

%%====================================================================
%% Harness
%%====================================================================

with_server(Fun) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Fun(maps:get(port, Server))
    after
        quic_test_echo_server:stop(Server)
    end.

connected_within(Conn, Budget) ->
    receive
        {quic, Conn, {connected, _}} -> ok;
        {quic, Conn, {closed, Reason}} -> ct:fail({closed_during_handshake, Reason})
    after Budget -> ct:fail("connect timeout")
    end.

%% One small echo over the finished connection: the retransmitted
%% flight must yield working application keys, not just a connected
%% event.
echo_roundtrip(Conn) ->
    {ok, StreamId} = quic:open_stream(Conn),
    Payload = <<"flight check">>,
    ok = quic:send_data(Conn, StreamId, Payload, true),
    ?assertEqual(Payload, collect_echo(Conn, StreamId, 5000, <<>>)).

collect_echo(Conn, StreamId, Budget, Acc) ->
    Start = erlang:monotonic_time(millisecond),
    receive
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            Acc1 = <<Acc/binary, Data/binary>>,
            case Fin of
                true -> Acc1;
                false -> collect_echo(Conn, StreamId, Budget - spent(Start), Acc1)
            end;
        {quic, Conn, _Other} ->
            collect_echo(Conn, StreamId, Budget - spent(Start), Acc)
    after max(0, Budget) -> Acc
    end.

spent(Start) ->
    max(1, erlang:monotonic_time(millisecond) - Start).

%% Client behind a socket adapter; the bridge relays to the server's
%% real UDP socket. For the first DropMs milliseconds everything the
%% server sends back is dropped; the client direction is never touched.
connect_through_bridge(Port, DropMs) ->
    ServerIP = {127, 0, 0, 1},
    SocketRef = make_ref(),
    Bridge = spawn_link(fun() -> bridge_init(ServerIP, Port, SocketRef, DropMs) end),
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
        socket_adapter => Adapter
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    Bridge ! {set_conn, Conn},
    {Conn, Bridge}.

bridge_init(ServerIP, ServerPort, SocketRef, DropMs) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    Deadline = erlang:monotonic_time(millisecond) + DropMs,
    bridge_loop(#{
        sock => Sock,
        conn => undefined,
        pending => [],
        drop_until => Deadline,
        server => {ServerIP, ServerPort},
        socket_ref => SocketRef
    }).

bridge_loop(#{sock := Sock, server := {ServerIP, ServerPort}} = Bridge) ->
    receive
        {set_conn, Conn} ->
            [deliver(Bridge, Conn, D) || D <- lists:reverse(maps:get(pending, Bridge))],
            bridge_loop(Bridge#{conn := Conn, pending := []});
        {send, _IP, _Port, Pkt} ->
            ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt),
            bridge_loop(Bridge);
        {udp, Sock, _IP, _Port, Data} ->
            case erlang:monotonic_time(millisecond) < maps:get(drop_until, Bridge) of
                true ->
                    bridge_loop(Bridge);
                false ->
                    case maps:get(conn, Bridge) of
                        undefined ->
                            bridge_loop(Bridge#{
                                pending := [Data | maps:get(pending, Bridge)]
                            });
                        Conn ->
                            deliver(Bridge, Conn, Data),
                            bridge_loop(Bridge)
                    end
            end;
        stop ->
            gen_udp:close(Sock);
        _ ->
            bridge_loop(Bridge)
    end.

deliver(#{server := {ServerIP, ServerPort}, socket_ref := SocketRef}, Conn, Data) ->
    Conn ! {udp, SocketRef, ServerIP, ServerPort, Data}.
