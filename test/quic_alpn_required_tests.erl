%%% -*- erlang -*-
%%%
%%% A connection that negotiates no application protocol is closed with
%%% no_application_protocol, 0x0178 (RFC 9001 Section 8.1).

-module(quic_alpn_required_tests).

-include_lib("eunit/include/eunit.hrl").

-define(WAIT_MS, 3000).
-define(NO_APPLICATION_PROTOCOL, 16#0178).

server_rejects_unknown_alpn_test_() ->
    {timeout, 20, fun() ->
        ?assertMatch(
            {peer_closed, transport, ?NO_APPLICATION_PROTOCOL, _, _},
            connect_and_await_close([<<"not-served">>])
        )
    end}.

client_rejects_missing_alpn_test_() ->
    {timeout, 20, fun() ->
        ok = meck:new(quic_tls, [passthrough]),
        ok = meck:expect(quic_tls, parse_encrypted_extensions, fun(Body) ->
            {ok, EE} = meck:passthrough([Body]),
            {ok, EE#{alpn := undefined}}
        end),
        try
            ?assertMatch(
                {tls_alert, no_application_protocol}, connect_and_await_close([<<"echo">>])
            )
        after
            meck:unload(quic_tls)
        end
    end}.

connect_and_await_close(Alpn) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => Alpn}),
        process_flag(trap_exit, true),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, maps:get(port, Server), Opts, self()),
        receive
            {quic, Conn, {closed, Reason}} -> Reason;
            {'EXIT', Conn, {tls_alert, _} = Reason} -> Reason
        after ?WAIT_MS -> timeout
        end
    after
        quic_test_echo_server:stop(Server)
    end.
