%%% -*- erlang -*-
%%%
%%% A TLS alert raised on the client must reach the server (issue #227).
%%%
%%% The alert is batched into the state send_tls_alert/2 returns, and the
%%% client sites exit immediately afterwards, so the batch has to be
%%% flushed before the process dies. The oracle here is deliberately the
%%% server's: the client notifies its owner *before* it tries to send, so
%%% asserting the client's own error proves nothing about the wire.

-module(quic_tls_alert_wire_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

client_alert_test_() ->
    {timeout, 30, fun a_client_alert_reaches_the_server/0}.

%% Force the server to answer with a well-formed ServerHello naming a
%% group the client did not select. That parses cleanly and fails the
%% negotiated-group check, which is an immediate-exit alert site.
a_client_alert_reaches_the_server() ->
    %% quic:connect/4 links the connection to the caller, and the client
    %% exits with {tls_alert, _} by design here.
    process_flag(trap_exit, true),
    Self = self(),
    ok = meck:new(quic_tls, [passthrough, unstick]),
    try
        ok = meck:expect(quic_tls, build_server_hello, fun(Opts) ->
            KeyPair = quic_crypto:generate_key_pair(secp256r1),
            meck:passthrough([
                Opts#{key_pair => KeyPair, key_share_group => secp256r1}
            ])
        end),
        {ok, Srv} = quic_test_echo_server:start(#{
            connection_handler => fun(ConnPid, _ConnRef) ->
                Watcher = spawn(fun() -> watch(ConnPid, Self) end),
                ok = quic:set_owner_sync(ConnPid, Watcher),
                {ok, Watcher}
            end
        }),
        try
            #{port := Port} = Srv,
            %% Default gen_udp backend, so send batching is on: with the
            %% adapter backend batching is disabled and the alert would
            %% go out immediately whether or not the flush is there.
            Opts = quic_test_echo_server:client_opts(),
            _ = quic:connect("127.0.0.1", Port, Opts, self()),
            receive
                {server_closed, Reason} ->
                    ?assertEqual(
                        {peer_closed, transport,
                            ?QUIC_CRYPTO_ERROR_BASE + ?TLS_ALERT_ILLEGAL_PARAMETER, 0,
                            <<"illegal parameter">>},
                        Reason
                    )
            after 5000 ->
                error(no_alert_on_the_wire)
            end
        after
            quic_test_echo_server:stop(Srv)
        end
    after
        meck:unload(quic_tls)
    end.

watch(Conn, Report) ->
    receive
        {quic, Conn, {closed, Reason}} ->
            Report ! {server_closed, Reason};
        {quic, Conn, _Other} ->
            watch(Conn, Report)
    after 20000 ->
        Report ! {server_closed, timeout}
    end.
