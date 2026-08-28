%%% -*- erlang -*-
%%%
%%% A connection on an MTU-limited path must survive its periodic PMTU
%%% raise probes (RFC 8899 §3, RFC 9000 §14.4).
%%%
%%% After the PMTU search settles, a raise timer re-probes toward
%%% pmtu_max_mtu to detect a path that has improved. On a path whose
%%% MTU sits below that ceiling the raise probe is lost by design,
%%% every time, forever. Probe loss belongs to the PMTUD state machine
%%% alone: tracked as ordinary in-flight data it inflates
%%% bytes_in_flight, arms the PTO machinery, and feeds spurious
%%% congestion events, and any liveness check keyed on unacknowledged
%%% in-flight data (a disconnect timeout) then declares a healthy peer
%%% dead. On a downstream deployment carrying such a check, every
%%% long-lived connection on an MTU-limited path (that is: most real
%%% WAN paths) died and reconnected once per raise interval, both ends
%%% at once.
%%%
%%% The harness caps the path at 1300 bytes with a size filter in the
%%% bridge: handshake and echo traffic (and the search probes that
%%% matter) fit; every raise probe above it is silently dropped. The
%%% raise interval is shortened so several probe-and-lose cycles run
%%% inside the observation window, and the case requires the
%%% connection to stay quiet-alive throughout and still carry data
%%% afterwards.
%%%
%%% Frame-level coverage of the same rule is in
%%% quic_pmtu_probe_loss_tests.

-module(quic_pmtu_raise_probe_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([control_unlimited_path/1, survives_raise_probes_on_limited_path/1]).

%% Path MTU cap: above every handshake/echo datagram, below the
%% 1500-byte probe ceiling, so only raise probes exceed it.
-define(PATH_LIMIT, 1300).
%% Raise probes fire quickly so several cycles fit in the window.
-define(RAISE_INTERVAL_MS, 1500).
%% A short disconnect timeout, for implementations that enforce one:
%% an in-flight-keyed liveness check turns the mistracked probe lethal
%% this soon after it is lost, so the case fails fast rather than
%% flaking.
-define(DISCONNECT_MS, 3000).
%% Quiet observation window: covers the search phase (probe timeouts
%% are >= 1 s each) plus several raise cycles, with margin. The window
%% is deliberately traffic-free: the failure mode needs an idle
%% connection, where the lost probe is the only thing in flight and
%% nothing else advances the progress clock. The keep-alive interval
%% sits above the disconnect timeout for the same reason, mirroring
%% the production configuration that hit this (keep-alive 20 s,
%% disconnect 16 s).
-define(OBSERVE_MS, 20000).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [control_unlimited_path, survives_raise_probes_on_limited_path].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Fence: same harness, no size cap. Holds with and without the fix and
%% tells a failure of the case below apart from a broken harness.
control_unlimited_path(_Config) ->
    run_echo_window(infinity).

survives_raise_probes_on_limited_path(_Config) ->
    run_echo_window(?PATH_LIMIT).

run_echo_window(Limit) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        {Conn, _Bridge} = connect_through_bridge(maps:get(port, Server), Limit),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 -> ct:fail("connect timeout")
        end,
        %% The path works when we start.
        echo_roundtrip(Conn, <<"before the raise probes">>),
        %% Stay quiet through the search and at least two raise cycles;
        %% only the connection's own keep-alives run. A disconnect in
        %% this window is exactly the bug.
        quiet_watch(Conn, erlang:monotonic_time(millisecond) + ?OBSERVE_MS),
        %% The same connection still carries data afterwards.
        echo_roundtrip(Conn, <<"after the raise probes">>),
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

quiet_watch(Conn, Deadline) ->
    Left = Deadline - erlang:monotonic_time(millisecond),
    case Left =< 0 of
        true ->
            ok;
        false ->
            receive
                {quic, Conn, {closed, Reason}} ->
                    ct:fail({connection_died_while_idle, Reason});
                {quic, Conn, _Other} ->
                    quiet_watch(Conn, Deadline)
            after Left -> ok
            end
    end.

echo_roundtrip(Conn, Payload) ->
    {ok, StreamId} = quic:open_stream(Conn),
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
        {quic, Conn, {closed, Reason}} ->
            ct:fail({connection_died_mid_echo, Reason});
        {quic, Conn, _Other} ->
            collect_echo(Conn, StreamId, Budget - spent(Start), Acc)
    after max(0, Budget) -> Acc
    end.

spent(Start) ->
    max(1, erlang:monotonic_time(millisecond) - Start).

%%====================================================================
%% Harness
%%====================================================================

%% Client behind a socket adapter; the bridge relays to the server's
%% real UDP socket and silently drops any datagram larger than Limit,
%% in both directions, which is exactly what a path with a smaller MTU
%% does to an unfragmentable QUIC datagram.
connect_through_bridge(Port, Limit) ->
    ServerIP = {127, 0, 0, 1},
    SocketRef = make_ref(),
    Bridge = spawn_link(fun() -> bridge_init(ServerIP, Port, SocketRef, Limit) end),
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
        pmtu_raise_interval => ?RAISE_INTERVAL_MS,
        disconnect_timeout => ?DISCONNECT_MS,
        keep_alive_interval => 5000,
        idle_timeout => 30000
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    Bridge ! {set_conn, Conn},
    {Conn, Bridge}.

fits(_Data, infinity) -> true;
fits(Data, Limit) -> byte_size(Data) =< Limit.

bridge_init(ServerIP, ServerPort, SocketRef, Limit) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    bridge_loop(#{
        sock => Sock,
        conn => undefined,
        pending => [],
        limit => Limit,
        server => {ServerIP, ServerPort},
        socket_ref => SocketRef
    }).

bridge_loop(#{sock := Sock, server := {ServerIP, ServerPort}, limit := Limit} = Bridge) ->
    receive
        {set_conn, Conn} ->
            [deliver(Bridge, Conn, D) || D <- lists:reverse(maps:get(pending, Bridge))],
            bridge_loop(Bridge#{conn := Conn, pending := []});
        {send, _IP, _Port, Pkt} ->
            Bin = iolist_to_binary(Pkt),
            case fits(Bin, Limit) of
                true -> ok = gen_udp:send(Sock, ServerIP, ServerPort, Bin);
                false -> ok
            end,
            bridge_loop(Bridge);
        {udp, Sock, _IP, _Port, Data} ->
            case fits(Data, Limit) of
                false ->
                    bridge_loop(Bridge);
                true ->
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
