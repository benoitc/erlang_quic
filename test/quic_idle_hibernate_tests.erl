%%% -*- erlang -*-
%%%
%%% Idle connection processes hibernate. The handshake leaves garbage
%%% pinned to a process that never collects on its own, which dominates
%%% the VM footprint once there are tens of thousands of quiet
%%% connections.

-module(quic_idle_hibernate_tests).

-include_lib("eunit/include/eunit.hrl").

hibernate_test_() ->
    {timeout, 60, fun an_idle_connection_shrinks/0}.

%% After the quiet period the process hibernates, which runs a fullsweep,
%% so the handshake and transfer garbage stops being pinned to a heap that
%% never collects on its own. The assertion is that collapse, not the
%% function the process parks in, which varies by release: erlang:hibernate/3
%% where gen_statem calls it, while on OTP 29 gen_statem calls
%% erlang:hibernate/0 and the process reports a gen_statem internal. Polled
%% rather than slept, so a slow runner that hibernates late still passes.
an_idle_connection_shrinks() ->
    with_connection(#{hibernate_after => 200}, fun(Conn) ->
        Busy = busiest_heap(Conn),
        %% hibernate_after counts from the last event, so wait for the
        %% connection to stop working before timing anything: under load
        %% the echo's tail traffic can still be arriving, and a heap that
        %% has not collapsed yet then says nothing about hibernation.
        ?assert(wait_until_quiet(Conn, 30000), "connection never went idle"),
        ?assert(quic_test_wait:until(fun() -> heap_words(Conn) * 4 =< Busy end, 10000))
    end).

%% True once the process has burned no reductions across a whole poll
%% interval, which is what `hibernate_after' waits for as well.
wait_until_quiet(Pid, Budget) ->
    Deadline = erlang:monotonic_time(millisecond) + Budget,
    quiet_loop(Pid, Deadline, reductions(Pid)).

quiet_loop(Pid, Deadline, Before) ->
    timer:sleep(250),
    case reductions(Pid) of
        Before ->
            true;
        Now ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> false;
                false -> quiet_loop(Pid, Deadline, Now)
            end
    end.

reductions(Pid) ->
    case process_info(Pid, reductions) of
        {reductions, N} -> N;
        undefined -> error(connection_died)
    end.

%% `infinity' opts out, for a deployment that would rather keep the heap
%% than pay a fullsweep on every quiet stretch. The connection then gives
%% gen_statem no hibernate_after at all. Checked at the option rather than
%% on a live heap: a live check can only show the heap did not shrink,
%% which any ordinary garbage collection can make false.
infinity_passes_no_hibernate_after_test() ->
    ?assertEqual([], quic_connection:statem_opts(#{hibernate_after => infinity})).

explicit_hibernate_after_is_passed_through_test() ->
    ?assertEqual(
        [{hibernate_after, 200}], quic_connection:statem_opts(#{hibernate_after => 200})
    ).

default_hibernate_after_test() ->
    ?assertEqual([{hibernate_after, 5000}], quic_connection:statem_opts(#{})).

%% Echo enough data to leave real garbage on the heap, and report the
%% largest heap seen while it was in flight. A single sample taken once
%% the echo has arrived can be a heap that already collapsed: the transfer
%% only has to pause for `hibernate_after', and the connection hibernates
%% mid-echo. Measured that way the heap looked four times smaller than its
%% peak before the test even started waiting.
busiest_heap(Conn) ->
    {ok, StreamId} = quic:open_stream(Conn),
    Payload = binary:copy(<<"x">>, 256 * 1024),
    ok = quic:send_data(Conn, StreamId, Payload, true),
    collect(Conn, StreamId, heap_words(Conn)).

collect(Conn, StreamId, Peak) ->
    receive
        {quic, Conn, {stream_data, StreamId, _Data, true}} ->
            max(Peak, heap_words(Conn));
        {quic, Conn, {stream_data, StreamId, _Data, false}} ->
            collect(Conn, StreamId, max(Peak, heap_words(Conn)))
    after 20000 ->
        Peak
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
