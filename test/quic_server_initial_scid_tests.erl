%%% -*- erlang -*-
%%%
%%% A client whose initial_source_connection_id does not match the
%%% Source Connection ID of its Initial packets is rejected (RFC 9000
%%% Section 7.3).

-module(quic_server_initial_scid_tests).

-include_lib("eunit/include/eunit.hrl").

-define(WAIT_MS, 3000).

mismatched_initial_scid_test_() ->
    {timeout, 20, fun mismatched_initial_scid/0}.

mismatched_initial_scid() ->
    ok = meck:new(quic_tls, [passthrough]),
    ok = meck:expect(quic_tls, build_client_hello, fun(#{transport_params := TP} = Opts) ->
        meck:passthrough([Opts#{transport_params := TP#{initial_scid => <<"not-our-scid">>}}])
    end),
    {ok, Server} = quic_test_echo_server:start(),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, maps:get(port, Server), Opts, self()),
        ?assertMatch({peer_closed, transport, 16#08, _, _}, await_close(Conn)),
        _ = quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server),
        meck:unload(quic_tls)
    end.

await_close(Conn) ->
    receive
        {quic, Conn, {closed, Reason}} -> Reason
    after ?WAIT_MS -> timeout
    end.
