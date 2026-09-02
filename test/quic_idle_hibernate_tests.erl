%%% -*- erlang -*-
%%%
%%% Idle connection processes hibernate. The handshake leaves garbage
%%% pinned to a process that never collects on its own, which dominates
%%% the VM footprint once there are tens of thousands of quiet
%%% connections.

-module(quic_idle_hibernate_tests).

-include_lib("eunit/include/eunit.hrl").

hibernate_test_() ->
    {timeout, 30, fun an_idle_connection_shrinks/0}.

stays_awake_test_() ->
    {timeout, 30, fun hibernation_can_be_turned_off/0}.

%% After the quiet period the process has run a fullsweep and parked:
%% a hibernated process reports no current function and a small heap.
%% Hibernation runs a fullsweep, so the handshake and transfer garbage
%% stops being pinned to a heap that never collects on its own. The
%% assertion is that collapse, not the internal function the process
%% parks in, which differs across OTP releases.
an_idle_connection_shrinks() ->
    with_connection(#{hibernate_after => 200}, fun(Conn) ->
        Busy = heap_after_work(Conn),
        timer:sleep(1500),
        Idle = heap_words(Conn),
        ?assert(Idle * 4 =< Busy)
    end).

%% `infinity' opts out, for a deployment that would rather keep the heap
%% than pay a fullsweep on every quiet stretch.
hibernation_can_be_turned_off() ->
    with_connection(#{hibernate_after => infinity}, fun(Conn) ->
        Busy = heap_after_work(Conn),
        timer:sleep(1500),
        Idle = heap_words(Conn),
        ?assert(Idle * 4 > Busy)
    end).

%% Echo enough data to leave real garbage on the heap, then report it.
heap_after_work(Conn) ->
    {ok, StreamId} = quic:open_stream(Conn),
    Payload = binary:copy(<<"x">>, 256 * 1024),
    ok = quic:send_data(Conn, StreamId, Payload, true),
    _ = collect(Conn, StreamId, <<>>),
    heap_words(Conn).

collect(Conn, StreamId, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect(Conn, StreamId, <<Acc/binary, Data/binary>>)
    after 20000 ->
        Acc
    end.

%%====================================================================
%% Helpers
%%====================================================================

with_connection(Extra, Fun) ->
    {ok, Srv} = quic_test_echo_server:start(),
    try
        #{port := Port} = Srv,
        Opts = maps:merge(quic_test_echo_server:client_opts(), Extra),
        {ok, Conn} = quic:connect("127.0.0.1", Port, Opts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 -> error(connect_timeout)
            end,
            Fun(Conn)
        after
            quic:safe_close(Conn, normal)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

heap_words(Pid) ->
    {total_heap_size, Words} = process_info(Pid, total_heap_size),
    Words.
