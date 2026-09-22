%%% -*- erlang -*-
%%%
%%% Failures a client has to be told about, rather than find by timing out.
%%%
%%% A server certificate the client does not trust has to fail the connect
%%% with the reason. A server that stops while its clients are connected
%%% has to close their connections, so a client waiting on a response hears
%%% that the connection is gone. The listener used to close its socket
%%% before its connections could send their CONNECTION_CLOSE, so a client
%%% heard nothing until its own idle timeout.
%%%
%%% Server and client run in this VM over 127.0.0.1.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_failures_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    untrusted_certificate_fails_a_sync_connect/1,
    untrusted_certificate_reaches_the_owner/1,
    stopping_the_server_closes_a_waiting_h3_client/1,
    stopping_the_server_closes_a_quic_client/1
]).

%% Well inside any idle timeout, so a close that never comes fails here.
-define(WAIT_MS, 2000).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        untrusted_certificate_fails_a_sync_connect,
        untrusted_certificate_reaches_the_owner,
        stopping_the_server_closes_a_waiting_h3_client,
        stopping_the_server_closes_a_quic_client
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    #{cert := OtherCA} = public_key:pkix_test_root_cert("Unrelated CA", []),
    [{cert, Cert}, {key, Key}, {other_ca, OtherCA} | Config].

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

untrusted_certificate_fails_a_sync_connect(Config) ->
    with_h3_server(Config, fun(_Name, Port) ->
        ?assertEqual(
            {error, {certificate_invalid, unknown_ca}},
            quic_h3:connect("127.0.0.1", Port, untrusting(Config, #{sync => true}))
        )
    end).

untrusted_certificate_reaches_the_owner(Config) ->
    with_h3_server(Config, fun(_Name, Port) ->
        {ok, Conn} = quic_h3:connect("127.0.0.1", Port, untrusting(Config, #{})),
        receive
            {quic_h3, Conn, {closed, Reason}} ->
                ?assertEqual({certificate_invalid, unknown_ca}, Reason)
        after ?WAIT_MS -> ct:fail(owner_not_told)
        end
    end).

%% The request is still being handled when the server stops.
stopping_the_server_closes_a_waiting_h3_client(Config) ->
    with_h3_server(Config, fun(Name, Port) ->
        {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{verify => false, sync => true}),
        {ok, _StreamId} = quic_h3:request(Conn, [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/slow">>},
            {<<":authority">>, <<"localhost">>}
        ]),
        receive
            handler_waiting -> ok
        after ?WAIT_MS -> ct:fail(no_request)
        end,
        ok = quic_h3:stop_server(Name),
        ?assertEqual(closed, await_h3_closed(Conn))
    end).

stopping_the_server_closes_a_quic_client(Config) ->
    {ok, Server} = quic_test_echo_server:start(),
    Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, maps:get(port, Server), Opts, self()),
    receive
        {quic, Conn, {connected, _}} -> ok
    after ?WAIT_MS -> ct:fail(connect_timeout)
    end,
    quic_test_echo_server:stop(Server),
    receive
        {quic, Conn, {closed, _Reason}} -> ok
    after ?WAIT_MS -> ct:fail(client_not_told)
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% Verifies the server against a CA that did not sign its certificate.
untrusting(Config, Extra) ->
    Extra#{verify => verify_peer, cacerts => [?config(other_ca, Config)]}.

with_h3_server(Config, F) ->
    Test = self(),
    Name = list_to_atom("h3_failures_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun(_Conn, _StreamId, _Method, _Path, _Headers) ->
            Test ! handler_waiting,
            timer:sleep(infinity)
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(Name, Port)
    after
        _ = quic_h3:stop_server(Name)
    end.

%% Whatever form the close takes, it is not a response.
await_h3_closed(Conn) ->
    receive
        {quic_h3, Conn, closed} -> closed;
        {quic_h3, Conn, {closed, _}} -> closed;
        {quic_h3, Conn, {goaway, _}} -> await_h3_closed(Conn);
        {quic_h3, Conn, {settings, _}} -> await_h3_closed(Conn);
        {quic_h3, Conn, {session_ticket, _}} -> await_h3_closed(Conn);
        {quic_h3, Conn, Other} -> {unexpected, Other}
    after ?WAIT_MS -> not_told
    end.
