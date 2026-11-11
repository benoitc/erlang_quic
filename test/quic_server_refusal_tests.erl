%%% -*- erlang -*-
%%%
%%% A client the server refuses is closed with CONNECTION_REFUSED at once
%%% instead of waiting for its handshake timeout (RFC 9000 Section 5.2.2).

-module(quic_server_refusal_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%% Far below the 30 s handshake timeout, generous for macOS loopback.
-define(WAIT_MS, 5000).

refused_test_() ->
    [
        {Name, {timeout, 20, fun() -> refused(Version, ServerOpts, Code) end}}
     || {Name, Version, ServerOpts, Code} <- [
            {"max_connections v1", ?QUIC_VERSION_1, #{max_connections => 0},
                ?QUIC_CONNECTION_REFUSED},
            {"max_connections v2", ?QUIC_VERSION_2, #{max_connections => 0},
                ?QUIC_CONNECTION_REFUSED},
            {"max_connections after a Retry", ?QUIC_VERSION_1,
                #{max_connections => 0, address_validation => always}, ?QUIC_CONNECTION_REFUSED},
            {"handler declines", ?QUIC_VERSION_1,
                #{connection_handler => fun(_Conn, _DCID) -> {error, overloaded} end},
                ?QUIC_CONNECTION_REFUSED},
            {"handler raises", ?QUIC_VERSION_1,
                #{connection_handler => fun(_Conn, _DCID) -> error(handler_bug) end},
                ?QUIC_INTERNAL_ERROR}
        ]
    ].

refused(Version, ServerOpts, Code) ->
    {ok, Server} = quic_test_echo_server:start(ServerOpts),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{
            alpn => [<<"echo">>], version => Version
        }),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, maps:get(port, Server), Opts, self()),
        ?assertMatch({peer_closed, transport, Code, 0, <<>>}, await_close(Conn)),
        _ = quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

await_close(Conn) ->
    receive
        {quic, Conn, {closed, Reason}} -> Reason
    after ?WAIT_MS -> timeout
    end.
