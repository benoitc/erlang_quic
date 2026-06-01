%%% -*- erlang -*-
%%%
%%% Unit tests for the HTTP/3 `early_data` state which opens H3
%%% critical streams + sends SETTINGS as 0-RTT, accepts requests as
%%% 0-RTT, and converges to `connected` (or `h3_connecting`) once
%%% QUIC is at 1-RTT and peer SETTINGS arrive.

-module(quic_h3_early_data_tests).

-include_lib("eunit/include/eunit.hrl").

setup() ->
    meck:new(quic, [passthrough]),
    meck:expect(quic, set_owner_sync, fun(_, _) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, has_early_keys, fun(_) -> true end),
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
    UniCounter = counters:new(1, []),
    BidiCounter = counters:new(1, []),
    meck:expect(quic, open_unidirectional_stream, fun(_) ->
        counters:add(UniCounter, 1, 1),
        N = counters:get(UniCounter, 1),
        %% Server-initiated uni streams use IDs 3, 7, 11... per RFC 9000.
        %% Client uses 2, 6, 10... For testing we just need fresh IDs.
        {ok, (N - 1) * 4 + 2}
    end),
    meck:expect(quic, open_stream, fun(_) ->
        counters:add(BidiCounter, 1, 1),
        N = counters:get(BidiCounter, 1),
        %% Client bidi: 0, 4, 8...
        {ok, (N - 1) * 4}
    end),
    meck:expect(quic, send_data, fun(_, _, _, _) -> ok end),
    ok.

teardown(_) ->
    meck:unload(quic),
    ok.

early_data_enter_opens_streams_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        ?assertEqual(early_data, current_state(H3Conn)),
        ?assert(meck:num_calls(quic, open_unidirectional_stream, '_') >= 3),
        ?assert(meck:num_calls(quic, send_data, '_') >= 1),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

early_data_request_sends_headers_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        Headers = [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":authority">>, <<"example.com">>},
            {<<":path">>, <<"/">>}
        ],
        Result = quic_h3_connection:request(H3Conn, Headers),
        ?assertMatch({ok, _StreamId}, Result),
        ?assertEqual(early_data, current_state(H3Conn)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

convergence_both_flags_advances_to_connected_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        send_peer_settings(H3Conn, FakeQuicConn),
        wait_settings_received(H3Conn, 500),
        ?assertEqual(early_data, current_state(H3Conn)),
        H3Conn ! {quic, FakeQuicConn, {connected, #{}}},
        wait_state(H3Conn, connected, 500),
        ?assertEqual(connected, current_state(H3Conn)),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

convergence_quic_first_falls_back_to_h3_connecting_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        {ok, H3Conn} = start_client_h3(FakeQuicConn),
        ok = quic_h3_connection:prime(H3Conn),
        wait_state(H3Conn, early_data, 500),
        H3Conn ! {quic, FakeQuicConn, {connected, #{}}},
        wait_state(H3Conn, h3_connecting, 500),
        ?assertEqual(h3_connecting, current_state(H3Conn)),
        %% RFC 9114 §6.2.1: a client opens exactly one control, one QPACK
        %% encoder, and one QPACK decoder stream. The fallback from
        %% early_data to h3_connecting must NOT re-run open_critical_streams.
        ?assertEqual(3, meck:num_calls(quic, open_unidirectional_stream, '_')),
        stop_h3(H3Conn, FakeQuicConn)
    end}.

%%% Helpers

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

%% Fake a peer SETTINGS frame arriving on a server-initiated control
%% stream. The peer first sends the stream type varint (0x00) followed
%% by the SETTINGS frame.
send_peer_settings(H3Conn, FakeQuicConn) ->
    %% Server-initiated uni stream uses ID 3 (RFC 9000).
    StreamId = 3,
    StreamTypeBin = quic_h3_frame:encode_stream_type(control),
    SettingsBin = quic_h3_frame:encode_settings(#{}),
    Payload = <<StreamTypeBin/binary, SettingsBin/binary>>,
    H3Conn ! {quic, FakeQuicConn, {stream_data, StreamId, Payload, false}},
    ok.

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
