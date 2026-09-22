%%% -*- erlang -*-
%%%
%%% Failures a client has to be told about, rather than find by timing out.
%%%
%%% A server certificate the client does not trust has to fail the connect
%%% with the reason.
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
    untrusted_certificate_reaches_the_owner/1
]).

%% Well inside any idle timeout, so a failure never reported fails here.
-define(WAIT_MS, 2000).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        untrusted_certificate_fails_a_sync_connect,
        untrusted_certificate_reaches_the_owner
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

%%====================================================================
%% Helpers
%%====================================================================

%% Verifies the server against a CA that did not sign its certificate.
untrusting(Config, Extra) ->
    Extra#{verify => verify_peer, cacerts => [?config(other_ca, Config)]}.

with_h3_server(Config, F) ->
    Name = list_to_atom("h3_failures_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun(_Conn, _StreamId, _Method, _Path, _Headers) -> ok end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(Name, Port)
    after
        _ = quic_h3:stop_server(Name)
    end.
