%%% -*- erlang -*-
%%%
%%% Regression test for issue #114.
%%%
%%% `quic:close(Conn, AppErrno)' must propagate AppErrno verbatim in
%%% the application CONNECTION_CLOSE frame. Before the fix, the
%%% integer reason fell through to the catch-all in
%%% `initiate_close/2' and the peer always saw `?QUIC_APPLICATION_ERROR'
%%% (12).

-module(quic_close_appcode_tests).

-include_lib("eunit/include/eunit.hrl").

close_with_integer_propagates_app_code_test_() ->
    {timeout, 10, fun close_with_integer_propagates_app_code/0}.

close_with_integer_propagates_app_code() ->
    AppCode = 16#42,
    {ok, Echo} = start_observer_server(),
    Port = maps:get(port, Echo),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
        {ok, ConnRef} = quic:connect("127.0.0.1", Port, Opts, self()),
        ok = wait_connected(ConnRef, 5000),
        ok = quic:close(ConnRef, AppCode),
        receive
            {server_close, Reason} ->
                ?assertMatch({peer_closed, application, AppCode, _}, Reason)
        after 5000 ->
            ?assert(false, server_did_not_observe_close)
        end
    after
        quic_test_echo_server:stop(Echo)
    end.

%% Sanity: integer 0 (NO_ERROR-equivalent) should also flow as an
%% application code, not be remapped to a transport error.
close_with_zero_propagates_app_code_test_() ->
    {timeout, 10, fun close_with_zero_propagates_app_code/0}.

close_with_zero_propagates_app_code() ->
    {ok, Echo} = start_observer_server(),
    Port = maps:get(port, Echo),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
        {ok, ConnRef} = quic:connect("127.0.0.1", Port, Opts, self()),
        ok = wait_connected(ConnRef, 5000),
        ok = quic:close(ConnRef, 0),
        receive
            {server_close, Reason} ->
                ?assertMatch({peer_closed, application, 0, _}, Reason)
        after 5000 ->
            ?assert(false, server_did_not_observe_close)
        end
    after
        quic_test_echo_server:stop(Echo)
    end.

%%====================================================================
%% Helpers
%%====================================================================

start_observer_server() ->
    TestPid = self(),
    quic_test_echo_server:start(#{
        connection_handler => fun(Conn, _ConnRef) ->
            Worker = spawn_link(fun() -> close_observer(Conn, TestPid) end),
            ok = quic:set_owner_sync(Conn, Worker),
            {ok, Worker}
        end
    }).

close_observer(Conn, TestPid) ->
    receive
        {quic, Conn, {closed, Reason}} ->
            TestPid ! {server_close, Reason};
        {quic, Conn, _Other} ->
            close_observer(Conn, TestPid);
        {'DOWN', _, process, Conn, _} ->
            ok
    after 10000 ->
        TestPid ! {server_close, timeout}
    end.

wait_connected(ConnRef, Timeout) ->
    receive
        {quic, ConnRef, {connected, _}} -> ok
    after Timeout ->
        {error, timeout}
    end.
