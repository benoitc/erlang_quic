%%% -*- erlang -*-
%%%
%%% Unit tests for the HTTP/3 `bootstrapping` state and `prime/1`
%%% mechanism. The client H3 connection now starts in `bootstrapping`
%%% and waits for a `prime` cast (sent by quic_h3:connect/3 after
%%% set_owner_sync returns) before deciding between 0-RTT and
%%% fresh-handshake paths.

-module(quic_h3_bootstrap_tests).

-include_lib("eunit/include/eunit.hrl").

setup() ->
    meck:new(quic, [passthrough]),
    meck:expect(quic, set_owner_sync, fun(_, _) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
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

bootstrap_to_early_data_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, has_early_keys, fun(_) -> true end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ?assertEqual(bootstrapping, current_state(H3Conn)),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        ?assertEqual(early_data, current_state(H3Conn)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

bootstrap_to_awaiting_quic_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, has_early_keys, fun(_) -> false end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ?assertEqual(bootstrapping, current_state(H3Conn)),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, awaiting_quic, 500),
        ?assertEqual(awaiting_quic, current_state(H3Conn)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

request_postponed_in_bootstrapping_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, has_early_keys, fun(_) -> true end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        Parent = self(),
        ReqPid = spawn(fun() ->
            Result = quic_h3_connection:request(H3Conn, [{<<":method">>, <<"GET">>}]),
            Parent ! {request_result, self(), Result}
        end),
        timer:sleep(20),
        ?assert(is_process_alive(ReqPid)),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        ?assertEqual(early_data, current_state(H3Conn)),
        exit(ReqPid, kill),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

connected_event_before_prime_does_not_strand_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, has_early_keys, fun(_) -> false end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        unlink(H3Conn),
        ?assertEqual(bootstrapping, current_state(H3Conn)),
        %% Send connected BEFORE prime — must be postponed, not dropped.
        H3Conn ! {quic, FakeQuicConn, {connected, #{}}},
        timer:sleep(20),
        ?assertEqual(bootstrapping, current_state(H3Conn)),
        ok = quic_h3_connection:prime(H3Conn),
        %% After prime, has_early_keys=false routes to awaiting_quic; the
        %% postponed connected message then replays in awaiting_quic and
        %% must advance the FSM beyond awaiting_quic. Without the fix the
        %% message was dropped by bootstrapping's catch-all and the H3
        %% connection was stranded in awaiting_quic forever.
        wait_state(H3Conn, h3_connecting, 500),
        FinalState = current_state(H3Conn),
        ?assertNotEqual(bootstrapping, FinalState),
        ?assertNotEqual(awaiting_quic, FinalState),
        ?assert(
            lists:member(FinalState, [h3_connecting, connected])
        ),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

stream_data_before_prime_is_postponed_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, has_early_keys, fun(_) -> false end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        unlink(H3Conn),
        ?assertEqual(bootstrapping, current_state(H3Conn)),
        H3Conn ! {quic, FakeQuicConn, {stream_data, 3, <<>>, false}},
        H3Conn ! {quic, FakeQuicConn, {new_stream, 7, uni}},
        timer:sleep(20),
        ?assertEqual(bootstrapping, current_state(H3Conn)),
        ?assert(is_process_alive(H3Conn)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

start_client_h3(QuicConn) ->
    quic_h3_connection:start_link(QuicConn, <<"example.com">>, 443, #{}).

current_state(Pid) ->
    {StateName, _StateData} = sys:get_state(Pid, 1000),
    StateName.

wait_state(_Pid, _Target, Timeout) when Timeout =< 0 ->
    ok;
wait_state(Pid, Target, Timeout) ->
    case current_state(Pid) of
        Target ->
            ok;
        _ ->
            timer:sleep(10),
            wait_state(Pid, Target, Timeout - 10)
    end.

stop_h3(H3Conn, FakeQuicConn) ->
    unlink(H3Conn),
    exit(H3Conn, shutdown),
    unlink(FakeQuicConn),
    exit(FakeQuicConn, shutdown),
    ok.

fake_quic_loop() ->
    receive
        stop -> ok;
        _ -> fake_quic_loop()
    end.
