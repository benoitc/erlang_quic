%%% -*- erlang -*-
%%%
%%% A QUIC connection that fails before HTTP/3 comes up (bad certificate,
%%% TLS alert, peer close) must surface its reason to the caller. The H3
%%% FSM used to drop those events in its pre-connected states, so
%%% `quic_h3:connect/3' with `sync => true' returned `connect_timeout' and
%%% the real reason was lost.

-module(quic_h3_connect_error_tests).

-include_lib("eunit/include/eunit.hrl").

-define(CERT_ERROR, {certificate_invalid, {hostname_mismatch, <<"example.com">>}}).

setup() ->
    meck:new(quic, [passthrough]),
    meck:expect(quic, set_owner_sync, fun(_Conn, _NewOwner) -> ok end),
    meck:expect(quic, close, fun(_) -> ok end),
    meck:expect(quic, close, fun(_, _, _) -> ok end),
    meck:expect(quic, safe_close, fun(_) -> ok end),
    meck:expect(quic, safe_close, fun(_, _, _) -> ok end),
    meck:expect(quic, datagram_max_size, fun(_) -> 0 end),
    meck:expect(quic, has_early_keys, fun(_) -> false end),
    meck:expect(quic, early_data_accepted, fun(_) -> unknown end),
    ok.

teardown(_) ->
    meck:unload(quic),
    ok.

%% The failure is already in the caller's mailbox when connect/3 hands the
%% connection to the H3 process (a certificate rejected during the
%% handshake, before ownership moved).
sync_connect_returns_failure_reason_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        meck:expect(quic, connect, fun(_Host, _Port, _Opts, Owner) ->
            Owner ! {quic, FakeQuicConn, {error, ?CERT_ERROR}},
            {ok, FakeQuicConn}
        end),
        Result = quic_h3:connect(<<"example.com">>, 443, #{
            sync => true, connect_timeout => 5000
        }),
        ?assertEqual({error, ?CERT_ERROR}, Result),
        stop(FakeQuicConn)
    end}.

%% The failure arrives while the H3 process is already waiting on QUIC.
late_failure_reaches_waiter_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        meck:expect(quic, connect, fun(_Host, _Port, _Opts, _Owner) ->
            {ok, FakeQuicConn}
        end),
        {ok, H3Conn} = quic_h3:connect(<<"example.com">>, 443, #{}),
        H3Conn ! {quic, FakeQuicConn, {error, ?CERT_ERROR}},
        ?assertEqual({error, ?CERT_ERROR}, quic_h3:wait_connected(H3Conn, 5000)),
        stop(FakeQuicConn)
    end}.

%% A peer close before HTTP/3 is up carries its reason the same way.
sync_connect_returns_close_reason_test_() ->
    {setup, fun setup/0, fun teardown/1, fun() ->
        FakeQuicConn = spawn_link(fun fake_quic_loop/0),
        meck:expect(quic, connect, fun(_Host, _Port, _Opts, Owner) ->
            Owner ! {quic, FakeQuicConn, {closed, {peer_closed, transport, 296, 0, <<>>}}},
            {ok, FakeQuicConn}
        end),
        Result = quic_h3:connect(<<"example.com">>, 443, #{
            sync => true, connect_timeout => 5000
        }),
        ?assertEqual({error, {peer_closed, transport, 296, 0, <<>>}}, Result),
        stop(FakeQuicConn)
    end}.

stop(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    ok.

fake_quic_loop() ->
    receive
        stop -> ok;
        _ -> fake_quic_loop()
    end.
