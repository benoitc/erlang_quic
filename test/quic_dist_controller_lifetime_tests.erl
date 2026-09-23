%%% -*- erlang -*-
%%%
%%% The dist controller lives exactly as long as the dist_util process
%%% it serves, and a connection that goes away fails the read that is
%%% waiting on it.
%%%
%%% `dist_util' assumes the socket closes when the handshake process
%%% terminates (dist_util.erl, "The termination of this process does
%%% also imply that the Socket is closed"). net_kernel relies on it to
%%% resolve a simultaneous connect: it kills the losing setup with
%%% `remarked', and the peer is supposed to notice the drop. Here the
%%% controller owns the connection, not the handshake process, so
%%% without these two rules the peer blocks in `recv_status' until
%%% dist_util's setup timer fires seconds later, and net_kernel keeps a
%%% pending entry for that node the whole time.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_dist_controller_lifetime_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Tests
%%====================================================================

%% net_kernel kills the losing setup process outright. The connection it
%% was handshaking over must not survive it.
handshake_owner_death_closes_the_connection_test() ->
    {Conn, Ctrl} = handshaking_controller(),
    Owner = blocked_reader(Ctrl),
    MRef = erlang:monitor(process, Ctrl),
    exit(Owner, remarked),
    ?assertMatch({ok, _}, wait_down(MRef, 2000)),
    ?assert(closed(Conn)),
    stop_conn(Conn).

%% Only the handshake process counts. Another process going down is
%% nothing to the controller.
only_the_handshake_owner_counts_test() ->
    {Conn, Ctrl} = handshaking_controller(),
    _Owner = blocked_reader(Ctrl),
    Unrelated = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    MRef = erlang:monitor(process, Ctrl),
    exit(Unrelated, kill),
    ?assertEqual(timeout, wait_down(MRef, 300)),
    ?assertNot(closed(Conn)),
    gen_statem:stop(Ctrl),
    stop_conn(Conn).

%% A read waiting on a connection that dies answers `{error, closed}',
%% which dist_util turns into a clean shutdown. Left unanswered it is the
%% caller that dies, out of a gen_statem call.
a_closed_connection_fails_the_pending_read_test() ->
    {Conn, Ctrl} = handshaking_controller(),
    Reader = reader(Ctrl),
    ok = wait_blocked(Reader, 2000),
    Ctrl ! {quic, Conn, {closed, normal}},
    ?assertEqual({ok, {error, closed}}, wait_read(Reader, 2000)),
    stop_conn(Conn).

a_transport_error_fails_the_pending_read_test() ->
    {Conn, Ctrl} = handshaking_controller(),
    Reader = reader(Ctrl),
    ok = wait_blocked(Reader, 2000),
    Ctrl ! {quic, Conn, {transport_error, 16#0a, protocol_violation}},
    ?assertEqual({ok, {error, closed}}, wait_read(Reader, 2000)),
    stop_conn(Conn).

%%====================================================================
%% Helpers
%%====================================================================

%% A controller in `handshaking', the state the dist handshake runs in,
%% over a connection stub that answers the calls a controller makes and
%% records whether it was closed.
handshaking_controller() ->
    Conn = fake_conn(),
    {ok, Ctrl} = quic_dist_controller:start_link(Conn, server, undefined),
    ok = wait_state(Ctrl, handshaking, 2000),
    %% Hand the controller back to a process that is not the test, so
    %% the test's own exit signals stay out of it.
    _ = erlang:unlink(Ctrl),
    {Conn, Ctrl}.

%% Stands in for the dist_util process: takes ownership, then blocks in
%% the read that `recv_status' blocks in.
blocked_reader(Ctrl) ->
    Parent = self(),
    Pid = spawn(fun() ->
        ok = quic_dist_controller:set_handshake_owner(Ctrl, self()),
        Parent ! {owner_ready, self()},
        catch quic_dist_controller:recv(Ctrl, 0, infinity)
    end),
    receive
        {owner_ready, Pid} -> ok
    after 2000 -> error(owner_never_started)
    end,
    ok = wait_blocked(Pid, 2000),
    Pid.

%% Reports what the read returned rather than dying with it.
reader(Ctrl) ->
    Parent = self(),
    spawn(fun() ->
        Result =
            try
                quic_dist_controller:recv(Ctrl, 0, infinity)
            catch
                Class:Reason -> {caught, Class, Reason}
            end,
        Parent ! {read_result, self(), Result}
    end).

%% The read has to be in flight before the connection goes away,
%% otherwise the test proves nothing about a pending one.
wait_blocked(_Pid, Left) when Left =< 0 ->
    {error, timeout};
wait_blocked(Pid, Left) ->
    case process_info(Pid, status) of
        {status, waiting} ->
            ok;
        _ ->
            timer:sleep(10),
            wait_blocked(Pid, Left - 10)
    end.

wait_read(Pid, Timeout) ->
    receive
        {read_result, Pid, Result} -> {ok, Result}
    after Timeout -> timeout
    end.

wait_down(MRef, Timeout) ->
    receive
        {'DOWN', MRef, process, _, Reason} -> {ok, Reason}
    after Timeout -> timeout
    end.

wait_state(_Ctrl, _State, Left) when Left =< 0 ->
    {error, timeout};
wait_state(Ctrl, State, Left) ->
    case element(1, sys:get_state(Ctrl)) of
        State ->
            ok;
        _ ->
            timer:sleep(10),
            wait_state(Ctrl, State, Left - 10)
    end.

%%--------------------------------------------------------------------
%% Connection stub
%%--------------------------------------------------------------------

%% Answers the gen_statem calls a controller makes at startup and
%% records the close so a test can assert the connection went with it.
fake_conn() ->
    spawn(fun() -> conn_loop(0, false) end).

conn_loop(NextStream, Closed) ->
    receive
        {'$gen_call', From, open_stream} ->
            gen_statem:reply(From, {ok, NextStream}),
            conn_loop(NextStream + 4, Closed);
        {'$gen_cast', {close, _}} ->
            conn_loop(NextStream, true);
        {'$gen_call', From, _Other} ->
            gen_statem:reply(From, ok),
            conn_loop(NextStream, Closed);
        {closed_p, Caller} ->
            Caller ! {closed_p, self(), Closed},
            conn_loop(NextStream, Closed);
        stop ->
            ok;
        _ ->
            conn_loop(NextStream, Closed)
    end.

closed(Conn) ->
    Conn ! {closed_p, self()},
    receive
        {closed_p, Conn, Value} -> Value
    after 2000 -> error(conn_stub_unresponsive)
    end.

stop_conn(Conn) ->
    Conn ! stop,
    ok.
