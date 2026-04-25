%%% -*- erlang -*-
%%%
%%% Regression test for issue #113.
%%%
%%% RFC 9000 §3.2 / §19.4: RESET_STREAM closes the SEND direction
%%% only. The recv side stays alive until the peer sends FIN or our
%%% local end issues STOP_SENDING. Calling
%%% `quic:reset_stream/3` followed by `quic:stop_sending/3' must
%%% therefore still emit STOP_SENDING — the stream entry must not be
%%% dropped after RESET_STREAM.

-module(quic_reset_stream_tests).

-include_lib("eunit/include/eunit.hrl").

reset_then_stop_sending_both_succeed_test_() ->
    %% This is an integration test against the in-process echo server,
    %% so wrap in a fixture to bound runtime.
    {timeout, 10, fun reset_then_stop_sending_both_succeed/0}.

reset_then_stop_sending_both_succeed() ->
    {ok, Echo} = quic_test_echo_server:start(),
    Port = maps:get(port, Echo),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
        {ok, ConnRef} = quic:connect("127.0.0.1", Port, Opts, self()),
        ok = wait_connected(ConnRef, 5000),
        {ok, StreamId} = quic:open_stream(ConnRef),
        ok = quic:send_data(ConnRef, StreamId, <<"hi">>, false),
        %% Issue #113: reset_stream must not drop the stream entry.
        %% stop_sending called after reset_stream MUST succeed (return
        %% `ok`), not `{error, unknown_stream}'.
        ok = quic:reset_stream(ConnRef, StreamId, 16#10),
        ?assertEqual(ok, quic:stop_sending(ConnRef, StreamId, 16#10)),
        quic:close(ConnRef, normal)
    after
        quic_test_echo_server:stop(Echo)
    end.

%% Reverse order — STOP_SENDING then RESET_STREAM — works on the
%% existing code; assert it stays green.
stop_sending_then_reset_both_succeed_test_() ->
    {timeout, 10, fun stop_sending_then_reset_both_succeed/0}.

stop_sending_then_reset_both_succeed() ->
    {ok, Echo} = quic_test_echo_server:start(),
    Port = maps:get(port, Echo),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
        {ok, ConnRef} = quic:connect("127.0.0.1", Port, Opts, self()),
        ok = wait_connected(ConnRef, 5000),
        {ok, StreamId} = quic:open_stream(ConnRef),
        ok = quic:send_data(ConnRef, StreamId, <<"hi">>, false),
        ok = quic:stop_sending(ConnRef, StreamId, 16#10),
        ?assertEqual(ok, quic:reset_stream(ConnRef, StreamId, 16#10)),
        quic:close(ConnRef, normal)
    after
        quic_test_echo_server:stop(Echo)
    end.

wait_connected(ConnRef, Timeout) ->
    receive
        {quic, ConnRef, {connected, _}} -> ok
    after Timeout ->
        {error, timeout}
    end.
