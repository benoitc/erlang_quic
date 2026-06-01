%%% -*- erlang -*-
%%%
%%% Unit tests for HTTP/3 event forwarding from the QUIC layer.
%%% Covers session_ticket and early_data_rejected forwarding to the H3
%%% owner, plus the synchronous early_data_accepted/1 accessor.

-module(quic_h3_event_forwarding_tests).

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
%% session_ticket forwarding
%%====================================================================

session_ticket_forwarded_from_bootstrapping_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        wait_state(H3Conn, bootstrapping, 500),
        Ticket = {ticket, <<"boot-ticket">>},
        H3Conn ! {quic, FakeQuicConn, {session_ticket, Ticket}},
        assert_owner_message({session_ticket, Ticket}, H3Conn, 500),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

session_ticket_forwarded_from_early_data_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        Ticket = {ticket, <<"opaque-ticket-bytes">>},
        H3Conn ! {quic, FakeQuicConn, {session_ticket, Ticket}},
        assert_owner_message({session_ticket, Ticket}, H3Conn, 500),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

session_ticket_forwarded_from_awaiting_quic_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, has_early_keys, fun(_) -> false end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, awaiting_quic, 500),
        Ticket = {ticket, <<"t1">>},
        H3Conn ! {quic, FakeQuicConn, {session_ticket, Ticket}},
        assert_owner_message({session_ticket, Ticket}, H3Conn, 500),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

session_ticket_forwarded_from_h3_connecting_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, has_early_keys, fun(_) -> false end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, awaiting_quic, 500),
        H3Conn ! {quic, FakeQuicConn, {connected, #{}}},
        wait_state(H3Conn, h3_connecting, 500),
        Ticket = {ticket, <<"t2">>},
        H3Conn ! {quic, FakeQuicConn, {session_ticket, Ticket}},
        assert_owner_message({session_ticket, Ticket}, H3Conn, 500),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

session_ticket_forwarded_from_connected_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        drive_to_connected(H3Conn, FakeQuicConn),
        Ticket = {ticket, <<"t3">>},
        H3Conn ! {quic, FakeQuicConn, {session_ticket, Ticket}},
        assert_owner_message({session_ticket, Ticket}, H3Conn, 500),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

session_ticket_forwarded_from_goaway_received_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        drive_to_connected(H3Conn, FakeQuicConn),
        send_peer_goaway(H3Conn, FakeQuicConn, 0),
        wait_state(H3Conn, goaway_received, 500),
        Ticket = {ticket, <<"t4">>},
        H3Conn ! {quic, FakeQuicConn, {session_ticket, Ticket}},
        assert_owner_message({session_ticket, Ticket}, H3Conn, 500),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

session_ticket_forwarded_from_goaway_sent_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        drive_to_connected(H3Conn, FakeQuicConn),
        ok = quic_h3_connection:goaway(H3Conn),
        wait_state(H3Conn, goaway_sent, 500),
        Ticket = {ticket, <<"t5">>},
        H3Conn ! {quic, FakeQuicConn, {session_ticket, Ticket}},
        assert_owner_message({session_ticket, Ticket}, H3Conn, 500),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

%%====================================================================
%% early_data_rejected forwarding and stream drop
%%====================================================================

early_data_rejected_forwarded_and_drops_streams_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        Headers = [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":authority">>, <<"example.com">>},
            {<<":path">>, <<"/a">>}
        ],
        {ok, SId0} = quic_h3_connection:request(H3Conn, Headers),
        {ok, SId1} = quic_h3_connection:request(H3Conn, Headers),
        {ok, SId2} = quic_h3_connection:request(H3Conn, Headers),
        Rejected = [SId0, SId2],
        H3Conn ! {quic, FakeQuicConn, {early_data_rejected, Rejected}},
        assert_owner_message({early_data_rejected, Rejected}, H3Conn, 500),
        {_StateName, StateData} = sys:get_state(H3Conn, 1000),
        _ = quic_h3_connection:test_stream(SId1, StateData),
        ?assertError({badkey, SId0}, quic_h3_connection:test_stream(SId0, StateData)),
        ?assertError({badkey, SId2}, quic_h3_connection:test_stream(SId2, StateData)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

early_data_rejected_forwarded_from_connected_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        drive_to_connected(H3Conn, FakeQuicConn),
        H3Conn ! {quic, FakeQuicConn, {early_data_rejected, []}},
        assert_owner_message({early_data_rejected, []}, H3Conn, 500),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

%%====================================================================
%% early_data_accepted accessor
%%====================================================================

early_data_accepted_true_in_early_data_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, early_data_accepted, fun(_) -> true end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        ?assertEqual(true, quic_h3:early_data_accepted(H3Conn)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

early_data_accepted_false_in_connected_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, early_data_accepted, fun(_) -> false end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        drive_to_connected(H3Conn, FakeQuicConn),
        ?assertEqual(false, quic_h3:early_data_accepted(H3Conn)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

early_data_accepted_unknown_in_bootstrapping_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        meck:expect(quic, early_data_accepted, fun(_) -> unknown end),
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ?assertEqual(bootstrapping, current_state(H3Conn)),
        ?assertEqual(unknown, quic_h3:early_data_accepted(H3Conn)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

%%====================================================================
%% Helpers
%%====================================================================

start_client_h3(QuicConn) ->
    quic_h3_connection:start_link(QuicConn, <<"example.com">>, 443, #{}).

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

drive_to_connected(H3Conn, FakeQuicConn) ->
    ok = quic_h3_connection:prime(H3Conn),
    wait_state(H3Conn, early_data, 500),
    send_peer_settings(H3Conn, FakeQuicConn),
    wait_settings_received(H3Conn, 500),
    H3Conn ! {quic, FakeQuicConn, {connected, #{}}},
    wait_state(H3Conn, connected, 500).

send_peer_settings(H3Conn, FakeQuicConn) ->
    StreamId = 3,
    StreamTypeBin = quic_h3_frame:encode_stream_type(control),
    SettingsBin = quic_h3_frame:encode_settings(#{}),
    Payload = <<StreamTypeBin/binary, SettingsBin/binary>>,
    H3Conn ! {quic, FakeQuicConn, {stream_data, StreamId, Payload, false}},
    ok.

send_peer_goaway(H3Conn, FakeQuicConn, GoawayId) ->
    StreamId = 3,
    Payload = quic_h3_frame:encode_goaway(GoawayId),
    H3Conn ! {quic, FakeQuicConn, {stream_data, StreamId, Payload, false}},
    ok.

assert_owner_message(Expected, H3Conn, Timeout) ->
    receive
        {quic_h3, H3Conn, Expected} -> ok
    after Timeout ->
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
