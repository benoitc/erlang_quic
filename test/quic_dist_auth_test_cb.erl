%%% -*- erlang -*-
%%%
%%% Test callbacks for quic_dist_auth_SUITE.
%%%

-module(quic_dist_auth_test_cb).

%% Each exported function matches the quic_dist_auth callback signature
%% `(Conn, Side, Timeout) -> {ok, _} | {error, _}'. The suite picks one
%% per test via the `auth_callback' Mod:Fun option.

-export([
    always_ok/3,
    server_denies/3,
    client_denies/3,
    hangs_forever/3
]).

always_ok(_Conn, _Side, _Timeout) ->
    {ok, ok}.

server_denies(_Conn, server, _Timeout) ->
    {error, denied};
server_denies(_Conn, client, _Timeout) ->
    {ok, ok}.

client_denies(_Conn, client, _Timeout) ->
    {error, denied};
client_denies(_Conn, server, _Timeout) ->
    {ok, ok}.

hangs_forever(_Conn, _Side, _Timeout) ->
    receive
        never -> ok
    end.
