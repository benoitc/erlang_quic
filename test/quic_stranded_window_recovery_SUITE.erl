%%% -*- erlang -*-
%%%
%%% Recovery after the whole send window is stranded.
%%%
%%% ACKs are per packet-number space (RFC 9000 §12.3) and packet numbers
%%% restart at 0 in each space. Only 1-RTT packets are registered in the
%%% connection's loss tracker, so a Handshake-space ACK of packet numbers
%%% 0..N applied to that tracker retires the first N 1-RTT packets
%%% without the peer ever having received them. They leave the sent
%%% queue, so nothing retransmits them, and the stream keeps a permanent
%%% hole.
%%%
%%% It takes a real outage to expose this. On a healthy path the 1-RTT
%%% packets are acknowledged before any late handshake-level ACK can
%%% retire them, which is why the control case below passes either way.
%%%
%%% The scenario here is a path that drops everything for long enough to
%%% strand a full window, then comes back: a WiFi-to-cellular handover, a
%%% VPN reconnect, a NAT rebind. The transfer has to complete once the
%%% path returns.
%%%
%%% Frame-level coverage of the same fix is in
%%% quic_handshake_ack_isolation_tests.

-module(quic_stranded_window_recovery_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([control_plain_echo/1, recovers_after_the_window_is_stranded/1]).

%% Several times the initial congestion window, so the send queue still
%% holds most of it when the outage starts.
-define(PAYLOAD_BYTES, 256 * 1024).
%% Long enough for the window to fill and for loss detection to run.
-define(BLACKHOLE_MS, 1500).
%% Budget for the whole transfer once the path is back. Recovery takes
%% well under a second when it works at all; this is deliberately loose
%% so the case fails on a stall rather than on a slow machine.
-define(RECOVER_MS, 20000).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [control_plain_echo, recovers_after_the_window_is_stranded].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Fence: the same transfer over the same harness with no outage. It
%% passes with and without the fix, and tells a failure of the case
%% below apart from a broken harness.
control_plain_echo(_Config) ->
    with_echo_server(fun(Conn) ->
        {ok, StreamId} = quic:open_stream(Conn),
        Payload = payload(),
        ok = quic:send_data_async(Conn, StreamId, Payload, true),
        Echoed = collect_echo(Conn, StreamId, ?RECOVER_MS, 0),
        ?assertEqual(byte_size(Payload), Echoed)
    end).

recovers_after_the_window_is_stranded(_Config) ->
    with_echo_server(fun(Conn, Bridge) ->
        %% Drop everything the client sends, so the window fills with
        %% packets that can never be acknowledged.
        Bridge ! blackhole,
        {ok, StreamId} = quic:open_stream(Conn),
        Payload = payload(),
        ok = quic:send_data_async(Conn, StreamId, Payload, true),
        timer:sleep(?BLACKHOLE_MS),

        Stranded = path_stats(Conn),
        ct:pal("at the end of the outage: ~p", [Stranded]),
        %% The premise: the window really is full. Without it the
        %% assertion below would pass on a connection that simply had
        %% nothing outstanding.
        ?assert(maps:get(bytes_in_flight, Stranded) >= maps:get(cwnd, Stranded)),

        Restored = erlang:monotonic_time(millisecond),
        Bridge ! heal,
        Echoed = collect_echo(Conn, StreamId, ?RECOVER_MS, 0),
        Elapsed = erlang:monotonic_time(millisecond) - Restored,
        ct:pal(
            "echoed ~p of ~p bytes, ~p ms after the path returned~nfinal: ~p",
            [Echoed, byte_size(Payload), Elapsed, path_stats(Conn)]
        ),
        ?assertEqual(byte_size(Payload), Echoed)
    end).

%%====================================================================
%% Harness
%%====================================================================

payload() ->
    binary:copy(<<"x">>, ?PAYLOAD_BYTES).

path_stats(Conn) ->
    {ok, Stats} = quic:get_path_stats(Conn),
    Stats.

with_echo_server(Fun) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        {Conn, Bridge} = connect_through_bridge(maps:get(port, Server)),
        case erlang:fun_info(Fun, arity) of
            {arity, 1} -> Fun(Conn);
            {arity, 2} -> Fun(Conn, Bridge)
        end,
        _ = quic:safe_close(Conn, normal),
        ok
    after
        quic_test_echo_server:stop(Server)
    end.

%% Accumulate echoed bytes until the payload is back or the budget runs
%% out. The budget covers the transfer as a whole, so a trickle that
%% never finishes still fails.
collect_echo(_Conn, _StreamId, Budget, Acc) when Budget =< 0 ->
    Acc;
collect_echo(_Conn, _StreamId, _Budget, Acc) when Acc >= ?PAYLOAD_BYTES ->
    Acc;
collect_echo(Conn, StreamId, Budget, Acc) ->
    Start = erlang:monotonic_time(millisecond),
    receive
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} ->
            collect_echo(Conn, StreamId, Budget - spent(Start), Acc + byte_size(Data));
        {quic, Conn, _Other} ->
            %% Session tickets and the like arrive on the same mailbox.
            collect_echo(Conn, StreamId, Budget - spent(Start), Acc)
    after Budget -> Acc
    end.

spent(Start) ->
    max(1, erlang:monotonic_time(millisecond) - Start).

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
        socket_adapter => Adapter
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    Bridge ! {set_conn, Conn},
    receive
        {quic, Conn, {connected, _}} -> {Conn, Bridge}
    after 10000 -> ct:fail("connect timeout")
    end.

%% Relays between the client's socket adapter and a real UDP socket to
%% the server. In blackhole mode client packets are dropped rather than
%% forwarded; `heal' puts the path back. The server direction is never
%% touched, so nothing else about the connection changes.
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
