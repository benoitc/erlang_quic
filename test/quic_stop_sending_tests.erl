%%% -*- erlang -*-
%%%
%%% A STOP_SENDING has to be answered with a RESET_STREAM.
%%%
%%% RFC 9000 Section 3.5: an endpoint that receives STOP_SENDING MUST send
%%% RESET_STREAM if its send side is still open, and SHOULD carry the error
%%% code the peer gave. The receiver asked because it no longer wants the
%%% data; the reset is what closes its side of the stream. Without it the
%%% peer is left waiting on a stream the sender has quietly stopped using.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_stop_sending_tests).

-include_lib("eunit/include/eunit.hrl").

%% Well under eunit's 5 s per-test limit, so a reset that never comes
%% fails on its assertion rather than as a timeout.
-define(WAIT_MS, 2000).

-define(CODE, 16#0107).

%% The echo server answers on the same stream and leaves its side open
%% while ours is, so its send side is still going when we ask it to stop.
stop_sending_is_answered_with_a_reset_test() ->
    with_echo_stream(fun(Conn, StreamId) ->
        ok = quic:stop_sending(Conn, StreamId, ?CODE),
        ?assertEqual({stream_reset, StreamId, ?CODE}, await_reset(Conn, StreamId))
    end).

%% The fence: without STOP_SENDING the server keeps its side open and
%% resets nothing, so the reset above is the answer to the request.
no_stop_sending_no_reset_test() ->
    with_echo_stream(fun(Conn, StreamId) ->
        ?assertEqual(timeout, await_reset(Conn, StreamId))
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% A connected client with one stream whose first write has been echoed,
%% neither side having sent FIN.
with_echo_stream(F) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Port = maps:get(port, Server),
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
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
        try
            F(Conn, StreamId)
        after
            _ = quic:close(Conn, normal)
        end
    after
        quic_test_echo_server:stop(Server)
    end.

await_reset(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_reset, StreamId, _} = Reset} -> Reset
    after ?WAIT_MS -> timeout
    end.
