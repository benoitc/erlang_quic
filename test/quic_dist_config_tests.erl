%%% -*- erlang -*-
%%%
%%% How QUIC distribution reads its security settings: the trust anchors
%%% a listener checks client certificates against, on both listener
%%% paths and whichever way the certificate is given, and malformed
%%% settings, which fail with {bad_config, _} instead of a default.
%%%
%%% Each case runs in a fresh peer node driven over standard_io, so the
%%% early-boot path (no quic application, standalone listener) and the
%%% supervised path can both be reached, and boot flags can be set.
-module(quic_dist_config_tests).

-include_lib("eunit/include/eunit.hrl").

-export([run_setup/0]).

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
%% Malformed settings
%%====================================================================

%% Each malformed setting fails startup with {bad_config, {Key, _}}
%% instead of falling back to a default.
bad_app_env_test_() ->
    {setup, fun pki/0, fun cleanup_pki/1, fun(Pki) ->
        Base = file_creds(Pki),
        [
            {Title, ?_assertMatch({error, {bad_config, {Key, _}}}, listen(early, Opts))}
         || {Title, Key, Opts} <- [
                {"verify atom", verify, Base ++ [{verify, bogus}]},
                {"verify boolean", verify, Base ++ [{verify, true}]},
                {"verify binary", verify, Base ++ [{verify, <<"verify_peer">>}]},
                {"auth_callback without colon", auth_callback,
                    Base ++ [{auth_callback, "nocolon"}]},
                {"auth_callback without function", auth_callback, Base ++ [{auth_callback, "m:"}]},
                {"auth_callback with two colons", auth_callback,
                    Base ++ [{auth_callback, "m:f:g"}]},
                {"auth_callback wrong arity", auth_callback,
                    Base ++ [{auth_callback, fun erlang:abs/1}]},
                {"auth_callback tuple", auth_callback, Base ++ [{auth_callback, {m}}]},
                {"psk_callback without module", psk_callback, Base ++ [{psk_callback, ":f"}]},
                {"psk_callback wrong arity", psk_callback,
                    Base ++ [{psk_callback, fun erlang:max/2}]},
                {"psk_callback atom", psk_callback, Base ++ [{psk_callback, foo}]},
                {"cacert integer", cacert, Base ++ [{cacert, 123}]},
                {"cacert empty list", cacert, Base ++ [{cacert, []}]},
                {"cacert list of atoms", cacert, Base ++ [{cacert, [foo]}]},
                {"cacert_file integer", cacert_file, Base ++ [{cacert_file, 42}]},
                {"cert_file integer", cert_file, [{cert_file, 1}, {key_file, "k.pem"}]},
                {"cert atom", cert, [{cert, foo}, {key, foo}]},
                {"cert without key", cert_and_key, [{cert, maps:get(cert, Pki)}]},
                {"cert_file without key_file", cert_and_key, [
                    {cert_file, maps:get(cert_file, Pki)}
                ]},
                {"external_psk unknown mode", external_psk,
                    Base ++ [{external_psk, {<<"id">>, <<"secret">>, [bogus]}}]}
            ]
        ] ++
            [
                {"dist not a list",
                    ?_assertMatch({error, {bad_config, {dist, bogus}}}, listen(early, bogus))}
            ]
    end}.

bad_boot_flag_test_() ->
    {setup, fun pki/0, fun cleanup_pki/1, fun(Pki) ->
        Base = file_creds(Pki),
        [
            {Title,
                ?_assertMatch(
                    {error, {bad_config, {Key, _}}}, listen(early, Base, Args)
                )}
         || {Title, Key, Args} <- [
                {"-quic_dist_verify value", verify, ["-quic_dist_verify", "bogus"]},
                {"-quic_dist_verify repeated", quic_dist_verify, [
                    "-quic_dist_verify", "verify_peer", "-quic_dist_verify", "verify_peer"
                ]},
                {"-quic_dist_cacert without value", quic_dist_cacert, ["-quic_dist_cacert"]},
                {"-quic_dist verify repeated", verify, [
                    "-quic_dist", "verify", "verify_peer", "-quic_dist", "verify", "verify_none"
                ]},
                {"verify in both flag forms", verify, [
                    "-quic_dist_verify", "verify_peer", "-quic_dist", "verify", "verify_peer"
                ]},
                {"-quic_dist without value", quic_dist, ["-quic_dist", "verify"]},
                {"-quic_dist unknown key", quic_dist, ["-quic_dist", "verfy", "verify_peer"]},
                {"-quic_dist auth_callback", auth_callback, [
                    "-quic_dist", "auth_callback", "nocolon"
                ]},
                {"-quic_dist psk_callback", psk_callback, ["-quic_dist", "psk_callback", "m:f:g"]}
            ]
        ]
    end}.

%% Well-formed values in each form still start.
good_settings_test_() ->
    {setup, fun pki/0, fun cleanup_pki/1, fun(Pki) ->
        Base = file_creds(Pki),
        CA = {cacert_file, maps:get(ca_file, Pki)},
        [
            {"verify_peer as a string",
                ?_assertMatch({ok, _}, listen(early, Base ++ [{verify, "verify_peer"}, CA]))},
            {"cacert as a list",
                ?_assertMatch(
                    {ok, _},
                    listen(early, Base ++ [{verify, verify_peer}, {cacert, [maps:get(ca, Pki)]}])
                )},
            {"callbacks as Module:Function",
                ?_assertMatch(
                    {ok, _},
                    listen(
                        early,
                        Base ++
                            [
                                {auth_callback, "quic_dist_auth_test_cb:always_ok"},
                                {psk_callback, "quic_dist_psk_test_cb:cluster"}
                            ]
                    )
                )},
            {"callbacks as funs and tuples",
                ?_assertMatch(
                    {ok, _},
                    listen(
                        early,
                        Base ++
                            [
                                {auth_callback, fun quic_dist_auth_test_cb:always_ok/3},
                                {psk_callback, {quic_dist_psk_test_cb, cluster}}
                            ]
                    )
                )},
            {"external_psk with modes",
                ?_assertMatch(
                    {ok, _},
                    listen(
                        early,
                        Base ++ [{external_psk, {<<"id">>, <<"secret">>, [psk_ke, psk_dhe_ke]}}]
                    )
                )},
            {"-quic_dist with several pairs applies each",
                ?_assertEqual(
                    {error, client_auth_needs_cacerts},
                    listen(early, Base, [
                        "-quic_dist",
                        "verify",
                        "verify_peer",
                        "auth_callback",
                        "quic_dist_auth_test_cb:always_ok"
                    ])
                )},
            {"-quic_dist and -quic_dist_Key for different keys",
                ?_assertMatch(
                    {ok, _},
                    listen(early, Base, [
                        "-quic_dist_verify",
                        "verify_peer",
                        "-quic_dist",
                        "cacert",
                        maps:get(ca_file, Pki)
                    ])
                )}
        ]
    end}.

%% Connection setup refuses a malformed setting before dialling.
setup_bad_config_test_() ->
    {setup, fun pki/0, fun cleanup_pki/1, fun(Pki) ->
        Base = file_creds(Pki),
        [
            {"malformed verify",
                ?_assertEqual(
                    {bad_config, {verify, bogus}},
                    setup_exit(Base ++ [{verify, bogus}])
                )},
            {"well-formed settings get past the config",
                ?_assertNotMatch({bad_config, _}, setup_exit(Base))}
        ]
    end}.

%% Exit reason of quic_dist:do_setup/6 dialling a node nothing answers
%% for.
setup_exit(DistOpts) ->
    Nodes = {nodes, [{'nobody@127.0.0.1', {{127, 0, 0, 1}, 9}}]},
    with_peer(early, DistOpts ++ [Nodes], [], fun(Peer) ->
        peer:call(Peer, ?MODULE, run_setup, [], 30000)
    end).

run_setup() ->
    process_flag(trap_exit, true),
    Pid = spawn_link(quic_dist, do_setup, [
        self(), 'nobody@127.0.0.1', normal, node(), longnames, 2000
    ]),
    receive
        {'EXIT', Pid, Reason} -> Reason
    after 20000 -> no_exit
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% quic_dist:listen/1 on a fresh peer: `early' leaves the quic
%% application stopped, so the standalone listener is used; `supervised'
%% starts it first.
listen(Mode, DistOpts) ->
    listen(Mode, DistOpts, []).

listen(Mode, DistOpts, Args) ->
    with_peer(Mode, DistOpts, Args, fun(Peer) ->
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
    Lib = code:lib_dir(quic),
    Idna = filename:dirname(code:which(idna)),
    Paths = ["-pa", filename:join(Lib, "ebin"), "-pa", Idna, "-pa", filename:join(Lib, "test")],
    {ok, Peer, _} = peer:start(#{connection => standard_io, args => Paths ++ Args}),
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
