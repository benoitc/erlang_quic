%%% -*- erlang -*-
%%%
%%% How QUIC distribution reads its security settings: the trust anchors
%%% a listener checks client certificates against, on both listener
%%% paths and whichever way the certificate is given.
%%%
%%% Each case runs in a fresh peer node driven over standard_io, so the
%%% early-boot path (no quic application, standalone listener) and the
%%% supervised path can both be reached, and boot flags can be set.
-module(quic_dist_config_tests).

-include_lib("eunit/include/eunit.hrl").

-define(SERVER, quic_dist_cfgtest).

%%====================================================================
%% Trust anchors
%%====================================================================

trust_anchor_test_() ->
    {setup, fun pki/0, fun cleanup_pki/1, fun(Pki) ->
        [
            {"early-boot listener refuses verify_peer without a CA",
                ?_assertEqual(
                    {error, client_auth_needs_cacerts},
                    listen(early, file_creds(Pki) ++ [{verify, verify_peer}])
                )},
            {"early-boot listener starts with verify_peer and a CA",
                ?_assertMatch(
                    {ok, _},
                    listen(
                        early,
                        file_creds(Pki) ++
                            [{verify, verify_peer}, {cacert_file, maps:get(ca_file, Pki)}]
                    )
                )},
            {"inline certificate uses cacert_file",
                ?_assertEqual(
                    {ok, [maps:get(ca, Pki)]},
                    server_cacerts(
                        inline_creds(Pki) ++
                            [{verify, verify_peer}, {cacert_file, maps:get(ca_file, Pki)}]
                    )
                )},
            {"certificate files use an inline cacert",
                ?_assertEqual(
                    {ok, [maps:get(ca, Pki)]},
                    server_cacerts(
                        file_creds(Pki) ++ [{verify, verify_peer}, {cacert, maps:get(ca, Pki)}]
                    )
                )},
            {"inline cacert and cacert_file are both trusted",
                ?_assertEqual(
                    {ok, [maps:get(other_ca, Pki), maps:get(ca, Pki)]},
                    server_cacerts(
                        inline_creds(Pki) ++
                            [
                                {verify, verify_peer},
                                {cacert, maps:get(other_ca, Pki)},
                                {cacert_file, maps:get(ca_file, Pki)}
                            ]
                    )
                )}
        ]
    end}.

%%====================================================================
%% Helpers
%%====================================================================

%% quic_dist:listen/1 on a fresh peer: `early' leaves the quic
%% application stopped, so the standalone listener is used; `supervised'
%% starts it first.
listen(Mode, DistOpts) ->
    with_peer(Mode, DistOpts, [], fun(Peer) ->
        strip(peer:call(Peer, quic_dist, listen, [cfgtest], 30000))
    end).

%% The trust anchors the supervised listener was started with.
server_cacerts(DistOpts) ->
    with_peer(supervised, DistOpts, [], fun(Peer) ->
        case peer:call(Peer, quic_dist, listen, [cfgtest], 30000) of
            {ok, _} ->
                {ok, #{opts := Opts}} = peer:call(Peer, quic, get_server_info, [?SERVER]),
                {ok, maps:get(cacerts, Opts, undefined)};
            Other ->
                Other
        end
    end).

with_peer(Mode, DistOpts, Args, Fun) ->
    Ebin = filename:join(code:lib_dir(quic), "ebin"),
    {ok, Peer, _} = peer:start(#{connection => standard_io, args => ["-pa", Ebin | Args]}),
    try
        case Mode of
            supervised -> {ok, _} = peer:call(Peer, application, ensure_all_started, [quic]);
            early -> ok
        end,
        ok = peer:call(Peer, application, set_env, [quic, dist_port, 0]),
        ok = peer:call(Peer, application, set_env, [quic, dist, DistOpts]),
        Fun(Peer)
    after
        peer:stop(Peer)
    end.

strip({ok, _}) -> {ok, listening};
strip(Other) -> Other.

file_creds(#{cert_file := C, key_file := K}) ->
    [{cert_file, C}, {key_file, K}].

inline_creds(#{cert := C, key := K}) ->
    [{cert, C}, {key, K}].

%% A CA and a node certificate it signs, as DER and as PEM files, and
%% an unrelated CA.
pki() ->
    Dir = filename:join(
        filename:basedir(user_cache, "quic_dist_config_tests"),
        integer_to_list(erlang:unique_integer([positive]))
    ),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Curve = {namedCurve, secp256r1},
    Root = public_key:pkix_test_root_cert("Dist CA", [{key, Curve}]),
    #{server_config := Server} = public_key:pkix_test_data(#{
        server_chain => #{root => Root, intermediates => [], peer => [{key, Curve}]},
        client_chain => #{root => Root, intermediates => [], peer => [{key, Curve}]}
    }),
    Cert = proplists:get_value(cert, Server),
    {KeyType, KeyDer} = proplists:get_value(key, Server),
    CA = maps:get(cert, Root),
    Write = fun(Name, Entries) ->
        Path = filename:join(Dir, Name),
        ok = file:write_file(Path, public_key:pem_encode(Entries)),
        Path
    end,
    #{
        dir => Dir,
        cert => Cert,
        key => public_key:der_decode(KeyType, KeyDer),
        ca => CA,
        other_ca => maps:get(cert, public_key:pkix_test_root_cert("Other CA", [{key, Curve}])),
        cert_file => Write("cert.pem", [{'Certificate', Cert, not_encrypted}]),
        key_file => Write("key.pem", [{KeyType, KeyDer, not_encrypted}]),
        ca_file => Write("ca.pem", [{'Certificate', CA, not_encrypted}])
    }.

cleanup_pki(#{dir := Dir}) ->
    _ = file:del_dir_r(Dir),
    ok.
