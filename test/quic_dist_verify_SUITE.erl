%%% -*- erlang -*-
%%%
%%% With `{verify, verify_peer}' and a `cacert_file', QUIC distribution
%%% authenticates both nodes by certificate: two nodes whose certificates
%%% chain to the configured CA connect, and a node whose CA is unrelated
%%% is refused.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_dist_verify_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([trusted_nodes_connect/1, untrusted_node_is_refused/1]).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [trusted_nodes_connect, untrusted_node_is_refused].

init_per_suite(Config) ->
    Dir = filename:join(?config(priv_dir, Config), "verify_certs"),
    case make_certs(Dir) of
        ok -> [{cert_dir, Dir} | Config];
        {error, Reason} -> {skip, Reason}
    end.

end_per_suite(_Config) ->
    ok.

trusted_nodes_connect(Config) ->
    ?assertEqual(pong, ping_with_ca(Config, "ca.pem")).

untrusted_node_is_refused(Config) ->
    ?assertEqual(pang, ping_with_ca(Config, "other_ca.pem")).

%% Two nodes with the CA-signed node certificate, each trusting CAFile;
%% the first pings the second.
ping_with_ca(Config, CAFile) ->
    Dir = ?config(cert_dir, Config),
    Certs = #{cert => filename:join(Dir, "node.pem"), key => filename:join(Dir, "node_key.pem")},
    Args = ["-quic_dist_verify", "verify_peer", "-quic_dist_cacert", filename:join(Dir, CAFile)],
    {ok, [#{peer := A}, #{node := B}] = Peers} = quic_dist_peer:start("verify", 2, Certs, Args),
    try
        peer:call(A, net_adm, ping, [B], 30000)
    after
        quic_dist_peer:stop(Peers)
    end.

%% A CA, a node certificate it signs for 127.0.0.1, and an unrelated CA.
make_certs(Dir) ->
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    F = fun(Name) -> filename:join(Dir, Name) end,
    Ext = F("san.ext"),
    ok = file:write_file(Ext, <<"subjectAltName=IP:127.0.0.1\n">>),
    Cmds = [
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Dist CA' "
            "-keyout ~s -out ~s",
            [F("ca_key.pem"), F("ca.pem")]
        ),
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Other CA' "
            "-keyout ~s -out ~s",
            [F("other_ca_key.pem"), F("other_ca.pem")]
        ),
        io_lib:format(
            "openssl req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' -keyout ~s -out ~s",
            [F("node_key.pem"), F("node.csr")]
        ),
        io_lib:format(
            "openssl x509 -req -in ~s -CA ~s -CAkey ~s -CAcreateserial -days 1 "
            "-extfile ~s -out ~s",
            [F("node.csr"), F("ca.pem"), F("ca_key.pem"), Ext, F("node.pem")]
        )
    ],
    lists:foreach(fun(C) -> os:cmd(lists:flatten(C) ++ " 2>/dev/null") end, Cmds),
    case lists:all(fun(N) -> filelib:is_file(F(N)) end, ["ca.pem", "other_ca.pem", "node.pem"]) of
        true -> ok;
        false -> {error, openssl_failed}
    end.
