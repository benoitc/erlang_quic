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

%% After the quiet period the process hibernates, which runs a fullsweep,
%% so the handshake and transfer garbage stops being pinned to a heap that
%% never collects on its own. The assertion is that collapse, not the
%% function the process parks in, which varies by release: erlang:hibernate/3
%% where gen_statem calls it, while on OTP 29 gen_statem calls
%% erlang:hibernate/0 and the process reports a gen_statem internal. Polled
%% rather than slept, so a slow runner that hibernates late still passes.
an_idle_connection_shrinks() ->
    with_connection(#{hibernate_after => 200}, fun(Conn) ->
        Busy = heap_after_work(Conn),
        ?assert(quic_test_wait:until(fun() -> heap_words(Conn) * 4 =< Busy end, 10000))
    end).

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
