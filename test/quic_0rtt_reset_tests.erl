%%% -*- erlang -*-
%%%
%%% RFC 9001 §4.6.2: when the server rejects 0-RTT, the client MUST
%%% reset stream state for every stream that carried 0-RTT data.
%%%
%%% Black-box coverage of the observable reset contract: drive a real
%%% quic_h3_connection (with the quic transport mocked), open 0-RTT
%%% requests in the `early_data' state, then deliver an
%%% `early_data_rejected' event and assert that the owner is notified and
%%% exactly the rejected streams are dropped. The QUIC-layer trigger
%%% paths (EncryptedExtensions without the early_data extension, and
%%% handshake completion with rejected early data) are exercised
%%% end-to-end by quic_h3_0rtt_SUITE.

-module(quic_0rtt_reset_tests).

-include_lib("eunit/include/eunit.hrl").

setup() ->
    meck:new(quic, [passthrough]),
    meck:expect(quic, set_owner_sync, fun(_, _) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
    meck:expect(quic, has_early_keys, fun(_) -> true end),
    meck:expect(quic, early_data_accepted, fun(_) -> unknown end),
    UniCounter = counters:new(1, []),
    BidiCounter = counters:new(1, []),
    meck:expect(quic, open_unidirectional_stream, fun(_) ->
        counters:add(UniCounter, 1, 1),
        N = counters:get(UniCounter, 1),
        {ok, (N - 1) * 4 + 2}
    end),
    meck:expect(quic, open_stream, fun(_) ->
        counters:add(BidiCounter, 1, 1),
        N = counters:get(BidiCounter, 1),
        {ok, (N - 1) * 4}
    end),
    meck:expect(quic, send_data, fun(_, _, _, _) -> ok end),
    ok.

teardown(_) ->
    meck:unload(quic),
    ok.

%%====================================================================
%% RFC 9001 §4.6.2 stream reset on 0-RTT rejection
%%====================================================================

%% A subset rejection drops exactly the rejected streams, leaves the
%% rest intact, and notifies the owner with the rejected ids.
rejection_drops_only_rejected_streams_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {H3Conn, FakeQuicConn} = start_in_early_data(),
        [SId0, SId1, SId2] = open_requests(H3Conn, 3),
        Rejected = [SId0, SId2],
        H3Conn ! {quic, FakeQuicConn, {early_data_rejected, Rejected}},
        assert_owner_message({early_data_rejected, Rejected}, H3Conn),
        StateData = state_data(H3Conn),
        assert_stream_present(SId1, StateData),
        assert_stream_absent(SId0, StateData),
        assert_stream_absent(SId2, StateData),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

%% Rejecting every outstanding 0-RTT stream drops them all.
rejection_of_all_streams_drops_all_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {H3Conn, FakeQuicConn} = start_in_early_data(),
        [SId0, SId1] = open_requests(H3Conn, 2),
        Rejected = [SId0, SId1],
        H3Conn ! {quic, FakeQuicConn, {early_data_rejected, Rejected}},
        assert_owner_message({early_data_rejected, Rejected}, H3Conn),
        StateData = state_data(H3Conn),
        assert_stream_absent(SId0, StateData),
        assert_stream_absent(SId1, StateData),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

%% An empty rejection set keeps every stream but still reaches the owner.
empty_rejection_keeps_streams_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        {H3Conn, FakeQuicConn} = start_in_early_data(),
        [SId0, SId1] = open_requests(H3Conn, 2),
        H3Conn ! {quic, FakeQuicConn, {early_data_rejected, []}},
        assert_owner_message({early_data_rejected, []}, H3Conn),
        StateData = state_data(H3Conn),
        assert_stream_present(SId0, StateData),
        assert_stream_present(SId1, StateData),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

%%====================================================================
%% Helpers
%%====================================================================

start_in_early_data() ->
    FakeQuicConn = spawn_link(fun fake_quic_loop/0),
    {ok, H3Conn} = quic_h3_connection:start_link(
        FakeQuicConn, <<"example.com">>, 443, #{}
    ),
    ok = quic_h3_connection:prime(H3Conn),
    wait_state(H3Conn, early_data, 500),
    {H3Conn, FakeQuicConn}.

open_requests(H3Conn, N) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ],
    [
        begin
            {ok, SId} = quic_h3_connection:request(H3Conn, Headers),
            SId
        end
     || _ <- lists:seq(1, N)
    ].

state_data(Pid) ->
    {_StateName, StateData} = sys:get_state(Pid, 1000),
    StateData.

assert_stream_present(SId, StateData) ->
    _ = quic_h3_connection:test_stream(SId, StateData),
    ok.

assert_stream_absent(SId, StateData) ->
    ?assertError({badkey, SId}, quic_h3_connection:test_stream(SId, StateData)).

wait_state(_Pid, Target, Timeout) when Timeout =< 0 ->
    erlang:error({timeout_waiting_for_state, Target});
wait_state(Pid, Target, Timeout) ->
    case sys:get_state(Pid, 1000) of
        {Target, _} ->
            ok;
        _ ->
            timer:sleep(10),
            wait_state(Pid, Target, Timeout - 10)
    end.

assert_owner_message(Expected, H3Conn) ->
    receive
        {quic_h3, H3Conn, Expected} -> ok
    after 500 ->
        erlang:error({timeout_waiting_for_owner_message, Expected})
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
