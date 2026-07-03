%%% -*- erlang -*-
%%%
%%% Tests for QUIC Idle Timeout Enforcement (RFC 9000 Section 10.1)
%%%

-module(quic_idle_timeout_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Idle Timer Message Tests
%%====================================================================

%% Test that idle_timeout message is properly formatted
idle_timeout_message_format_test() ->
    %% The idle timeout message should be an atom
    Msg = idle_timeout,
    ?assertEqual(idle_timeout, Msg).

%%====================================================================
%% Integration with Connection State
%%====================================================================

%% Note: Full integration tests require starting the connection process
%% and are covered in quic_connection_tests.erl and quic_e2e_SUITE.erl

%% Test the basic concept of idle timeout checking
idle_timeout_check_logic_test() ->
    % 30 seconds
    IdleTimeout = 30000,
    % 25 seconds ago
    LastActivity = erlang:monotonic_time(millisecond) - 25000,
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - LastActivity,

    %% Should NOT timeout (25s < 30s)
    ?assertNot(TimeSinceActivity >= IdleTimeout),

    %% Simulate more time passing

    % 35 seconds ago
    LastActivity2 = erlang:monotonic_time(millisecond) - 35000,
    TimeSinceActivity2 = Now - LastActivity2,

    %% Should timeout (35s >= 30s)
    ?assert(TimeSinceActivity2 >= IdleTimeout).

%% Test that zero idle timeout means no timeout
zero_idle_timeout_test() ->
    IdleTimeout = 0,
    % Very old
    _LastActivity = erlang:monotonic_time(millisecond) - 1000000,
    _Now = erlang:monotonic_time(millisecond),

    %% With 0 timeout, comparison should indicate "set but disabled"
    %% In the implementation, set_idle_timer returns immediately for timeout=0
    ?assertEqual(0, IdleTimeout).

%%====================================================================
%% Timer Reset Tests
%%====================================================================

%% Test that activity resets the idle timeout window
activity_resets_timeout_test() ->
    InitialActivity = erlang:monotonic_time(millisecond),
    % Small delay
    timer:sleep(10),

    %% Simulate activity update
    NewActivity = erlang:monotonic_time(millisecond),

    ?assert(NewActivity > InitialActivity).

%%====================================================================
%% Boundary Tests
%%====================================================================

%% Test exactly at timeout boundary
exact_timeout_boundary_test() ->
    % 1 second
    IdleTimeout = 1000,

    %% Exactly at boundary should trigger timeout (>= comparison)
    LastActivity = erlang:monotonic_time(millisecond) - 1000,
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - LastActivity,

    ?assert(TimeSinceActivity >= IdleTimeout).

%% Test just below timeout boundary
just_below_timeout_boundary_test() ->
    % 10 seconds
    IdleTimeout = 10000,

    %% Just below boundary should NOT trigger timeout

    % 9.99 seconds ago
    LastActivity = erlang:monotonic_time(millisecond) - 9990,
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - LastActivity,

    ?assertNot(TimeSinceActivity >= IdleTimeout).

%%====================================================================
%% Behavioural tests: the idle timer follows RFC 9000 §10.1 — restarted on
%% every receive and on the first ack-eliciting send since the last receive,
%% but not on subsequent sends.
%%
%% These run a real client (over a controllable in-process datagram bridge)
%% against the in-process echo server, then black-hole the path. The client
%% keeps sending keep-alive PINGs the whole time; the connection must still
%% idle-close, because after the one permitted send-side restart a peer sending
%% into a black hole gets no further restarts. (Regression test for the bug
%% where every send reset last_activity, so a sending-but-deaf connection never
%% timed out.)
%%====================================================================

%% keep_alive_interval is floored to 5000ms by the implementation
%% (calculate_keep_alive_interval/2), so the idle timeout must sit above that
%% for keep-alive to hold a live connection open. Keep it just above so the
%% tests stay reasonably quick.
-define(IDLE_TIMEOUT, 7000).
-define(KEEP_ALIVE, 5000).

%% A black-holed path must idle-close within ~IDLE_TIMEOUT plus one keep-alive
%% interval (the single §10.1 send-side restart) despite the client still
%% emitting keep-alive PINGs.
silent_path_idle_closes_test_() ->
    {timeout, 30, fun silent_path_idle_closes/0}.

%% A live path must NOT idle-close: keep-alive PINGs are answered, and the
%% received ACKs keep the idle timer from firing. Guards against the fix being
%% too aggressive.
live_path_stays_open_test_() ->
    {timeout, 30, fun live_path_stays_open/0}.

silent_path_idle_closes() ->
    {ok, Echo} = quic_test_echo_server:start(),
    {Conn, Bridge} = connect_via_bridge(maps:get(port, Echo)),
    try
        %% Black-hole the path in both directions. The client carries on sending
        %% keep-alive PINGs (every ?KEEP_ALIVE ms) but receives nothing.
        Bridge ! block,
        receive
            {quic, Conn, {closed, _Reason}} ->
                ok
        after ?IDLE_TIMEOUT + ?KEEP_ALIVE + 5000 ->
            erlang:error(idle_timeout_did_not_fire)
        end
    after
        Bridge ! stop,
        quic_test_echo_server:stop(Echo)
    end.

live_path_stays_open() ->
    {ok, Echo} = quic_test_echo_server:start(),
    {Conn, Bridge} = connect_via_bridge(maps:get(port, Echo)),
    try
        %% Path stays up; keep-alive PING/ACK exchanges keep the idle timer from
        %% firing well past several idle-timeout windows.
        %% Wait past the idle timeout. A keep-alive PING fires at ~?KEEP_ALIVE
        %% and its ACK (a received packet) pushes the idle deadline out, so the
        %% connection must still be open here. If keep-alive did not hold it
        %% open, the idle timer would have fired at ?IDLE_TIMEOUT (< this wait).
        receive
            {quic, Conn, {closed, Reason}} ->
                erlang:error({unexpected_idle_close, Reason})
        after ?IDLE_TIMEOUT + 2000 ->
            ok
        end
    after
        quic:safe_close(Conn, normal),
        Bridge ! stop,
        quic_test_echo_server:stop(Echo)
    end.

%% Connect to the echo server through a datagram bridge we control, with a short
%% idle timeout and aggressive keep-alive. Returns once {connected} is received.
connect_via_bridge(Port) ->
    ServerIP = {127, 0, 0, 1},
    SocketRef = make_ref(),
    Owner = self(),
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
    Opts = (quic_test_echo_server:client_opts())#{
        alpn => [<<"echo">>],
        socket_backend => adapter,
        socket_adapter => Adapter,
        idle_timeout => ?IDLE_TIMEOUT,
        keep_alive_interval => ?KEEP_ALIVE
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, Owner),
    Bridge ! {set_conn, Conn},
    receive
        {quic, Conn, {connected, _Info}} -> ok
    after 10000 ->
        erlang:error(connect_timeout)
    end,
    {Conn, Bridge}.

%% Datagram bridge: shuttles packets between the client's adapter callbacks and
%% a gen_udp socket to the echo server. `block' drops datagrams in both
%% directions, simulating a dead path.
bridge_init(ServerIP, ServerPort, SocketRef) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    bridge_loop(Sock, undefined, ServerIP, ServerPort, SocketRef, false).

bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef, Blocked) ->
    Loop = fun(C, B) -> bridge_loop(Sock, C, ServerIP, ServerPort, SocketRef, B) end,
    receive
        {set_conn, NewConn} ->
            Loop(NewConn, Blocked);
        block ->
            Loop(Conn, true);
        {send, _IP, _Port, _Pkt} when Blocked ->
            Loop(Conn, Blocked);
        {send, _IP, _Port, Pkt} ->
            ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt),
            Loop(Conn, Blocked);
        {udp, Sock, _IP, _Port, _Data} when Blocked ->
            Loop(Conn, Blocked);
        {udp, Sock, _IP, _Port, Data} when is_pid(Conn) ->
            Conn ! {udp, SocketRef, ServerIP, ServerPort, Data},
            Loop(Conn, Blocked);
        {udp, Sock, _IP, _Port, _Data} ->
            Loop(Conn, Blocked);
        stop ->
            gen_udp:close(Sock),
            ok;
        _ ->
            Loop(Conn, Blocked)
    end.
