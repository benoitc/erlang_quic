%%% -*- erlang -*-
%%%
%%% Regression test for the HTTP/3 connect owner-transfer race.
%%%
%%% quic_h3:connect/3 opens the QUIC connection owned by the caller, then
%%% transfers ownership to the H3 process via set_owner_sync/2. On fast
%%% handshakes (localhost, low-RTT, 0-RTT) — and on the Happy Eyeballs race
%%% path, where the connection handshakes while owned by the race
%%% coordinator — the QUIC `connected' event and the peer's control-stream
%%% SETTINGS arrive in the (transient) owner's mailbox before that transfer.
%%% set_owner re-emits `connected' to the new owner but cannot replay the
%%% already-delivered stream_data, so the H3 FSM never receives SETTINGS,
%%% never converges, and the caller blocks until connect_timeout. connect/3
%%% must drain and forward the leaked `{quic, QuicConn, _}' stream events to
%%% the H3 process after the ownership transfer.

-module(quic_h3_connect_race_tests).

-include_lib("eunit/include/eunit.hrl").

setup() ->
    meck:new(quic, [passthrough]),
    %% Mirror the real set_owner_sync/2: in the `connected' state it
    %% re-emits `connected' to the new owner. It does NOT replay already
    %% delivered stream data, so the leaked SETTINGS can only reach the H3
    %% FSM if connect/3 drains and forwards them.
    meck:expect(quic, set_owner_sync, fun(Conn, NewOwner) ->
        NewOwner ! {quic, Conn, {connected, #{}}},
        ok
    end),
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
        %% Reproduce the race: quic:connect/4 returns with the QUIC
        %% `connected' event AND the peer's control-stream SETTINGS already
        %% sitting in the caller's mailbox, because a transient process (the
        %% caller, or the Happy Eyeballs coordinator that handed off to it)
        %% was the owner when they arrived.
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

%% The server's close can also land just after the hand-off, while the
%% H3 process opens its streams. The connection tells its owner first,
%% then fails the call, as a draining connection does. connect/3 returns
%% the close, and the caller, which does not trap exits, stays up.
closed_while_opening_streams_test_() ->
    Closed = {peer_closed, transport, 16#174, 0, <<"certificate required">>},
    FailOpen = fun(Conn) ->
        self() ! {quic, Conn, {closed, Closed}},
        {error, {invalid_state, draining}}
    end,
    {foreach, fun setup/0, fun teardown/1, [
        {"opening a stream fails", fun() ->
            meck:expect(quic, open_unidirectional_stream, FailOpen),
            ?assertEqual({error, Closed}, connect_to_fake())
        end}
        | [
            {"send " ++ integer_to_list(N) ++ " fails", fun() ->
                fail_send(N, Closed),
                ?assertEqual({error, Closed}, connect_to_fake())
            end}
         || N <- [1, 2, 3, 4]
        ]
    ]}.

%% Sends 1 to 3 write the stream types, send 4 the SETTINGS frame.
fail_send(N, Closed) ->
    Count = counters:new(1, []),
    meck:expect(quic, send_data, fun(Conn, _, _, _) ->
        counters:add(Count, 1, 1),
        case counters:get(Count, 1) of
            N ->
                self() ! {quic, Conn, {closed, Closed}},
                {error, {invalid_state, draining}};
            _ ->
                ok
        end
    end).

%% In a caller of its own that does not trap exits, so a linked process
%% going down shows up as `{caller_died, Reason}'.
connect_to_fake() ->
    FakeQuicConn = spawn(fun fake_quic_loop/0),
    meck:expect(quic, connect, fun(_Host, _Port, _Opts, _Owner) -> {ok, FakeQuicConn} end),
    Self = self(),
    {Pid, MRef} = spawn_monitor(fun() ->
        Self !
            {
                self(),
                quic_h3:connect(<<"example.com">>, 443, #{sync => true, connect_timeout => 1000})
            }
    end),
    try
        receive
            {Pid, Result} ->
                erlang:demonitor(MRef, [flush]),
                Result;
            {'DOWN', MRef, process, Pid, Reason} ->
                {caller_died, Reason}
        after 5000 -> timeout
        end
    after
        FakeQuicConn ! stop
    end.

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
