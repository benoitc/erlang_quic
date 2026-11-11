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
    hangs_forever/3,
    reports_peer_node/3
]).

%% Logger handler, so a test can read the reports a node logged.
-export([log/2]).

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

%% Claims to have authenticated the node named by the `-qauth_peer_node'
%% boot argument, on either side.
reports_peer_node(_Conn, _Side, _Timeout) ->
    {ok, [[Name]]} = init:get_argument(qauth_peer_node),
    {ok, {authenticated_node, list_to_atom(Name)}}.

%% Appends each report's what/authenticated/claimed keys to the file in
%% the handler config, synchronously, so nothing is lost on halt.
log(#{msg := {report, #{what := _} = Report}}, #{config := #{file := File}}) ->
    Kept = maps:with([what, authenticated, claimed], Report),
    ok = file:write_file(File, io_lib:format("~p.~n", [Kept]), [append]);
log(_Event, _Config) ->
    ok.
