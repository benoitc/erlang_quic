%%% -*- erlang -*-
%%% Listener auth-method contract: QUIC has no unauthenticated mode
%%% (RFC 9001 §3), so a listener must carry either X.509 credentials
%%% or a TLS 1.3 external PSK (RFC 8446 §4.2.11) before it starts.

-module(quic_server_auth_tests).

-include_lib("eunit/include/eunit.hrl").

-define(IDENTITY, <<"alice">>).
-define(SECRET, <<"this-is-a-32-byte-test-secret!!!">>).

auth_method_test_() ->
    {setup, fun setup/0, fun cleanup/1, [
        fun no_auth_method_rejected/0,
        fun psks_accepted/0,
        fun psk_callback_accepted/0,
        fun sni_callback_accepted/0
    ]}.

setup() ->
    {ok, Started} = application:ensure_all_started(quic),
    Started.

cleanup(_Started) ->
    ok.

%% No cert/key, no PSK, no sni_callback: refused up front with a
%% clean error rather than a listener that dies after start returns.
no_auth_method_rejected() ->
    Name = server_name(),
    ?assertEqual(
        {error, no_auth_method},
        quic:start_server(Name, 0, #{alpn => [<<"echo">>]})
    ),
    ?assertMatch({error, _}, quic:get_server_port(Name)).

%% A static PSK table is a complete auth method on its own; no cert
%% or key is needed.
psks_accepted() ->
    assert_starts(#{psks => #{?IDENTITY => ?SECRET}}).

psk_callback_accepted() ->
    Cb = fun
        (?IDENTITY) -> {ok, ?SECRET};
        (_) -> not_found
    end,
    assert_starts(#{psk_callback => Cb}).

%% sni_callback supplies cert/key per handshake, so it counts even
%% with no static cert/key configured.
sni_callback_accepted() ->
    assert_starts(#{sni_callback => fun(_SNI) -> {error, no_cert} end}).

assert_starts(Extra) ->
    Name = server_name(),
    Opts = maps:merge(#{alpn => [<<"echo">>]}, Extra),
    ?assertMatch({ok, _}, quic:start_server(Name, 0, Opts)),
    ?assertMatch({ok, _Port}, quic:get_server_port(Name)),
    ok = quic:stop_server(Name).

server_name() ->
    list_to_atom(
        "quic_auth_test_" ++
            integer_to_list(erlang:unique_integer([positive, monotonic]))
    ).
