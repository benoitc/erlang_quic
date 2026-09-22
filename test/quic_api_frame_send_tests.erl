%%% -*- erlang -*-
%%%
%%% A frame queued through the API has to leave straight away.
%%%
%%% quic:reset_stream/3, quic:reset_stream_at/4, quic:stop_sending/3
%%% and quic:send_ping/1 queue a frame on the connection. Like any other
%%% API call that queues a frame, the call has to hand it to the socket
%%% before returning, or it waits for whatever traffic next flushes the
%%% connection, which on a quiet connection may never come.
%%%
%%% Each case counts the datagrams the client socket writes during the
%%% call, so it does not depend on the peer receiving them in time. PMTU
%%% discovery is off on both sides: its probes would otherwise write
%%% datagrams of their own for a second or two after connect.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_api_frame_send_tests).

-include_lib("eunit/include/eunit.hrl").

-define(WAIT_MS, 2000).

-define(CODE, 16#0107).

reset_stream_is_sent_by_the_call_test() ->
    with_quiet_stream(#{}, fun(Conn, StreamId) ->
        ?assert(sends(Conn, fun() -> ok = quic:reset_stream(Conn, StreamId, ?CODE) end))
    end).

reset_stream_at_is_sent_by_the_call_test() ->
    with_quiet_stream(#{reset_stream_at => true}, fun(Conn, StreamId) ->
        ?assert(sends(Conn, fun() -> ok = quic:reset_stream_at(Conn, StreamId, ?CODE, 0) end))
    end).

stop_sending_is_sent_by_the_call_test() ->
    with_quiet_stream(#{}, fun(Conn, StreamId) ->
        ?assert(sends(Conn, fun() -> ok = quic:stop_sending(Conn, StreamId, ?CODE) end))
    end).

send_ping_is_sent_by_the_call_test() ->
    with_quiet_stream(#{}, fun(Conn, _StreamId) ->
        ?assert(sends(Conn, fun() -> ok = quic:send_ping(Conn) end))
    end).

%% The fence: a call that queues nothing writes nothing, so what the
%% cases above count is the frame their call sent. A timer already due
%% on the connection can write during any one call, so the fence holds if
%% one of a few calls writes nothing.
a_call_that_queues_nothing_sends_nothing_test() ->
    with_quiet_stream(#{}, fun(Conn, _StreamId) ->
        NoOp = fun() -> {ok, _} = quic:get_stats(Conn) end,
        ?assert(lists:any(fun(_) -> not sends(Conn, NoOp) end, lists:seq(1, 3)))
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% Whether the client socket wrote a datagram while Call ran.
sends(Conn, Call) ->
    Before = quic_connection_test_support:datagrams_sent(Conn),
    Call(),
    quic_connection_test_support:datagrams_sent(Conn) > Before.

%% A connected client with one open stream whose first write has been
%% echoed, and nothing left in flight on either side.
with_quiet_stream(Extra, F) ->
    Quiet = Extra#{pmtu_enabled => false},
    {ok, Server} = quic_test_echo_server:start(Quiet),
    try
        Port = maps:get(port, Server),
        Opts = maps:merge(quic_test_echo_server:client_opts(), Quiet#{alpn => [<<"echo">>]}),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?WAIT_MS -> error(connect_timeout)
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, <<"ping">>, false),
        receive
            {quic, Conn, {stream_data, StreamId, <<"ping">>, false}} -> ok
        after ?WAIT_MS -> error(no_echo)
        end,
        %% Let the ACKs for the exchange settle so nothing else is due to
        %% leave the client while a call runs.
        timer:sleep(200),
        try
            F(Conn, StreamId)
        after
            _ = quic:close(Conn, normal)
        end
    after
        quic_test_echo_server:stop(Server)
    end.
