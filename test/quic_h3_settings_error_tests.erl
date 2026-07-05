%%% -*- erlang -*-
%%%
%%% Regression tests for HTTP/3 client SETTINGS error handling.
%%%
%%% A peer SETTINGS frame that fails validation (RFC 9114 §7.2.4 /
%%% RFC 9297 §2.1) must close the connection with H3_SETTINGS_ERROR,
%%% never crash the gen_statem. apply_peer_settings/2 signals such
%%% violations with throw({connection_error, ...}); gen_statem treats a
%%% throw from a state callback as its return value, so an uncaught throw
%%% terminates the process with bad_return_from_state_function and, because
%%% the connection is start_link'd to its owner, takes the owner down too.

-module(quic_h3_settings_error_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

setup() ->
    meck:new(quic, [passthrough]),
    meck:expect(quic, set_owner_sync, fun(_, _) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, safe_close, fun(_) -> ok end),
    meck:expect(quic, safe_close, fun(_, _, _) -> ok end),
    %% Peer never advertised QUIC max_datagram_frame_size.
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
    meck:expect(quic, has_early_keys, fun(_) -> true end),
    meck:expect(quic, early_data_accepted, fun(_) -> unknown end),
    UniCounter = counters:new(1, []),
    meck:expect(quic, open_unidirectional_stream, fun(_) ->
        counters:add(UniCounter, 1, 1),
        N = counters:get(UniCounter, 1),
        {ok, (N - 1) * 4 + 2}
    end),
    meck:expect(quic, open_stream, fun(_) -> {ok, 0} end),
    meck:expect(quic, send_data, fun(_, _, _, _) -> ok end),
    ok.

teardown(_) ->
    meck:unload(quic),
    ok.

%%====================================================================
%% SETTINGS_H3_DATAGRAM=1 without QUIC datagram support -> clean close
%%====================================================================

h3_datagram_without_quic_support_closes_cleanly_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        assert_settings_close(#{h3_datagram => 1})
    end}.

%%====================================================================
%% Invalid SETTINGS_H3_DATAGRAM value (not 0 or 1) -> clean close
%%====================================================================

invalid_h3_datagram_value_closes_cleanly_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        assert_settings_close(#{h3_datagram => 2})
    end}.

%%====================================================================
%% Valid SETTINGS must not trip the error path (no false positive)
%%====================================================================

valid_settings_keep_connection_alive_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        process_flag(trap_exit, true),
        FakeQuic = spawn(fun fake_quic_loop/0),
        {ok, H3} = start_client_h3(FakeQuic),
        ok = quic_h3_connection:prime(H3),
        wait_state(H3, early_data, 500),
        send_peer_settings(H3, FakeQuic, #{}),
        wait_settings_received(H3, 500),
        no_error_event(H3, 150),
        ?assertEqual(#{}, quic_h3_connection:get_peer_settings(H3)),
        ?assert(is_process_alive(H3)),
        stop_h3(H3, FakeQuic)
    end}.

%%====================================================================
%% Helpers
%%====================================================================

%% Deliver an invalid peer SETTINGS frame and assert the owner sees a
%% clean H3_SETTINGS_ERROR and the gen_statem terminates `normal' rather
%% than crashing with bad_return_from_state_function.
assert_settings_close(Settings) ->
    process_flag(trap_exit, true),
    FakeQuic = spawn(fun fake_quic_loop/0),
    {ok, H3} = start_client_h3(FakeQuic),
    MRef = monitor(process, H3),
    ok = quic_h3_connection:prime(H3),
    wait_state(H3, early_data, 500),
    send_peer_settings(H3, FakeQuic, Settings),
    receive
        {quic_h3, H3, {error, ErrCode, _Phrase}} ->
            ?assertEqual(?H3_SETTINGS_ERROR, ErrCode)
    after 1000 ->
        erlang:error(no_settings_error_event)
    end,
    receive
        {'DOWN', MRef, process, H3, Reason} ->
            ?assertEqual(normal, Reason)
    after 1000 ->
        erlang:error(process_did_not_terminate)
    end,
    stop_h3(H3, FakeQuic).

start_client_h3(QuicConn) ->
    quic_h3_connection:start_link(QuicConn, <<"example.com">>, 443, #{}).

send_peer_settings(H3, FakeQuic, Settings) ->
    StreamId = 3,
    TypeBin = quic_h3_frame:encode_stream_type(control),
    SettingsBin = quic_h3_frame:encode_settings(Settings),
    H3 ! {quic, FakeQuic, {stream_data, StreamId, <<TypeBin/binary, SettingsBin/binary>>, false}},
    ok.

current_state(Pid) ->
    {StateName, _StateData} = sys:get_state(Pid, 1000),
    StateName.

wait_state(_Pid, Target, Timeout) when Timeout =< 0 ->
    erlang:error({timeout_waiting_for_state, Target});
wait_state(Pid, Target, Timeout) ->
    case current_state(Pid) of
        Target ->
            ok;
        _ ->
            timer:sleep(10),
            wait_state(Pid, Target, Timeout - 10)
    end.

wait_settings_received(_Pid, Timeout) when Timeout =< 0 ->
    erlang:error(timeout_waiting_for_peer_settings);
wait_settings_received(Pid, Timeout) ->
    case quic_h3_connection:get_peer_settings(Pid) of
        undefined ->
            timer:sleep(10),
            wait_settings_received(Pid, Timeout - 10);
        _ ->
            ok
    end.

no_error_event(H3, Timeout) ->
    receive
        {quic_h3, H3, {error, _, _}} = Msg -> erlang:error({unexpected_error_event, Msg})
    after Timeout ->
        ok
    end.

stop_h3(H3, FakeQuic) ->
    unlink(H3),
    exit(H3, shutdown),
    unlink(FakeQuic),
    exit(FakeQuic, shutdown),
    ok.

fake_quic_loop() ->
    receive
        stop -> ok;
        _ -> fake_quic_loop()
    end.
