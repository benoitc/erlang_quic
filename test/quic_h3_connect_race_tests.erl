%%% -*- erlang -*-
%%%
%%% Regression test for the HTTP/3 connect owner-transfer race.
%%%
%%% quic_h3:connect/3 opens the QUIC connection owned by the caller, then
%%% transfers ownership to the H3 process via set_owner_sync/2. On fast
%%% handshakes (localhost, low-RTT, 0-RTT) the QUIC `connected' event and
%%% the peer's control-stream SETTINGS arrive in the caller's mailbox
%%% before that transfer. set_owner_sync re-emits `connected' to the new
%%% owner but cannot replay the already-delivered stream_data, so the H3
%%% FSM never receives SETTINGS, never converges, and the caller blocks
%%% until connect_timeout. connect/3 must drain and forward the leaked
%%% `{quic, QuicConn, _}' owner events to the H3 process after the
%%% ownership transfer.

-module(quic_h3_connect_race_tests).

-include_lib("eunit/include/eunit.hrl").

setup() ->
    meck:new(quic, [passthrough]),
    %% set_owner_sync is a no-op here so the ONLY way the H3 FSM can learn
    %% it is connected and that the peer sent SETTINGS is via connect/3
    %% draining and forwarding the leaked owner events.
    meck:expect(quic, set_owner_sync, fun(_, _) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
    meck:expect(quic, has_early_keys, fun(_) -> false end),
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

leaked_owner_events_forwarded_to_h3_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        Payload = control_settings_payload(),
        %% Reproduce the fast-handshake race: quic:connect/4 returns with
        %% the QUIC `connected' event AND the peer's control-stream
        %% SETTINGS already sitting in the caller's mailbox, because the
        %% caller is still the owner at this point.
        meck:expect(quic, connect, fun(_Host, _Port, _Opts, Owner) ->
            Owner ! {quic, FakeQuicConn, {connected, #{}}},
            Owner ! {quic, FakeQuicConn, {stream_data, 3, Payload, false}},
            {ok, FakeQuicConn}
        end),
        Result = quic_h3:connect(<<"example.com">>, 443, #{
            sync => true, connect_timeout => 1000
        }),
        ?assertMatch({ok, _}, Result),
        {ok, H3Conn} = Result,
        cleanup(H3Conn, FakeQuicConn)
    end}.

control_settings_payload() ->
    StreamTypeBin = quic_h3_frame:encode_stream_type(control),
    SettingsBin = quic_h3_frame:encode_settings(#{}),
    <<StreamTypeBin/binary, SettingsBin/binary>>.

cleanup(H3Conn, FakeQuicConn) ->
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
