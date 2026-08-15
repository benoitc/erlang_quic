%%% -*- erlang -*-
%%% Key-exchange input validation: a peer key share that does not fit
%%% the negotiated group, and a `groups' option this runtime cannot
%%% perform, must both surface as errors rather than crashing inside
%%% crypto mid-handshake.

-module(quic_kex_tests).

-include_lib("eunit/include/eunit.hrl").

hybrid_supported() ->
    quic_crypto:group_supported(x25519mlkem768).

%%====================================================================
%% Peer key-share length validation
%%====================================================================

%% A client share of the wrong length for the group it named.
server_key_exchange_rejects_bad_share_test() ->
    ?assertEqual(
        {error, illegal_parameter},
        quic_crypto:server_key_exchange(x25519, <<1, 2, 3>>)
    ),
    ?assertEqual(
        {error, illegal_parameter},
        quic_crypto:server_key_exchange(secp256r1, <<0:32/unit:8>>)
    ).

server_key_exchange_rejects_bad_hybrid_share_test_() ->
    {setup, fun() -> ok end, fun(_) -> ok end, [
        fun() ->
            case hybrid_supported() of
                false ->
                    ok;
                true ->
                    %% Hybrid client share is 1184 + 32 bytes; a bare
                    %% X25519 key must not reach the encapsulation.
                    ?assertEqual(
                        {error, illegal_parameter},
                        quic_crypto:server_key_exchange(x25519mlkem768, <<0:32/unit:8>>)
                    )
            end
        end
    ]}.

%% Server answers with a share that doesn't match the negotiated group.
compute_shared_secret_rejects_bad_share_test() ->
    {_Pub, Priv} = quic_crypto:generate_key_pair(x25519),
    ?assertEqual(
        {error, illegal_parameter},
        quic_crypto:compute_shared_secret(x25519, Priv, <<1, 2, 3>>)
    ),
    %% RFC 8446 §7.4.2 requires the X25519 all-zero check.
    ?assertEqual(
        {error, illegal_parameter},
        quic_crypto:compute_shared_secret(x25519, Priv, <<0:32/unit:8>>)
    ).

compute_shared_secret_rejects_group_mismatch_test_() ->
    {setup, fun() -> ok end, fun(_) -> ok end, [
        fun() ->
            case hybrid_supported() of
                false ->
                    ok;
                true ->
                    {_Pub, Priv} = quic_crypto:generate_key_pair(x25519mlkem768),
                    %% Hybrid private key, classical-sized server share.
                    ?assertEqual(
                        {error, illegal_parameter},
                        quic_crypto:compute_shared_secret(
                            x25519mlkem768, Priv, <<0:32/unit:8>>
                        )
                    ),
                    %% Hybrid private key against a classical group.
                    ?assertEqual(
                        {error, illegal_parameter},
                        quic_crypto:compute_shared_secret(x25519, Priv, <<0:32/unit:8>>)
                    )
            end
        end
    ]}.

%% The happy paths still agree on a secret.
classical_exchange_still_agrees_test() ->
    {ClientPub, ClientPriv} = quic_crypto:generate_key_pair(x25519),
    {ServerPub, _ServerPriv, ServerSecret} =
        quic_crypto:server_key_exchange(x25519, ClientPub),
    ?assertEqual(
        ServerSecret,
        quic_crypto:compute_shared_secret(x25519, ClientPriv, ServerPub)
    ).

hybrid_exchange_still_agrees_test_() ->
    {setup, fun() -> ok end, fun(_) -> ok end, [
        fun() ->
            case hybrid_supported() of
                false ->
                    ok;
                true ->
                    {ClientPub, ClientPriv} = quic_crypto:generate_key_pair(x25519mlkem768),
                    {ServerPub, _, ServerSecret} =
                        quic_crypto:server_key_exchange(x25519mlkem768, ClientPub),
                    ?assertEqual(
                        ServerSecret,
                        quic_crypto:compute_shared_secret(
                            x25519mlkem768, ClientPriv, ServerPub
                        )
                    )
            end
        end
    ]}.

hybrid_invalid_input_alerts_test_() ->
    {setup, fun() -> ok end, fun(_) -> ok end, [
        fun() ->
            case hybrid_supported() of
                false ->
                    ok;
                true ->
                    %% FIPS 203 encapsulation-key check failure.
                    InvalidEK = binary:copy(<<16#ff>>, 1184),
                    ?assertEqual(
                        {error, illegal_parameter},
                        quic_crypto:server_key_exchange(
                            x25519mlkem768, <<InvalidEK/binary, 9:256>>
                        )
                    ),

                    %% Both hybrid peers must reject an invalid/all-zero
                    %% X25519 component with illegal_parameter.
                    {EK, _DK} = crypto:generate_key(mlkem768, []),
                    ?assertEqual(
                        {error, illegal_parameter},
                        quic_crypto:server_key_exchange(
                            x25519mlkem768, <<EK/binary, 0:256>>
                        )
                    ),
                    {_ClientShare, {MlKemDK, XPriv}} =
                        quic_crypto:generate_key_pair(x25519mlkem768),
                    ?assertEqual(
                        {error, illegal_parameter},
                        quic_crypto:compute_shared_secret(
                            x25519mlkem768,
                            {MlKemDK, XPriv},
                            <<0:1088/unit:8, 0:256>>
                        )
                    ),

                    %% A non-length ML-KEM decapsulation failure is a
                    %% local/internal error under draft §4.2.
                    ?assertEqual(
                        {error, internal_error},
                        quic_crypto:compute_shared_secret(
                            x25519mlkem768,
                            {<<>>, XPriv},
                            <<0:1088/unit:8, 9:256>>
                        )
                    )
            end
        end
    ]}.

server_hello_preserves_and_validates_group_test_() ->
    {setup, fun() -> ok end, fun(_) -> ok end, [
        fun() ->
            case hybrid_supported() of
                false ->
                    ok;
                true ->
                    {ClientShare, _ClientPriv} =
                        quic_crypto:generate_key_pair(x25519mlkem768),
                    {ServerShare, undefined, _Secret} =
                        quic_crypto:server_key_exchange(x25519mlkem768, ClientShare),
                    {Msg, _} = quic_tls:build_server_hello(#{
                        key_pair => {ServerShare, undefined},
                        key_share_group => x25519mlkem768
                    }),
                    <<_:8, _:24, Body/binary>> = Msg,
                    {ok, Parsed} = quic_tls:parse_server_hello(Body),
                    ?assertEqual(x25519mlkem768, maps:get(selected_group, Parsed)),

                    %% The same bytes labeled as a different group do not
                    %% become acceptable merely because the parser used to
                    %% discard the NamedGroup code.
                    {Mislabeled, _} = quic_tls:build_server_hello(#{
                        key_pair => {ServerShare, undefined},
                        key_share_group => secp256r1
                    }),
                    <<_:8, _:24, BadBody/binary>> = Mislabeled,
                    ?assertEqual(
                        {error, illegal_parameter},
                        quic_tls:parse_server_hello(BadBody)
                    )
            end
        end
    ]}.

%%====================================================================
%% group_supported/1
%%====================================================================

%% Only groups quic_tls has a wire code for are negotiable. x448 has a
%% constant but no code point, so claiming support for it would let a
%% `groups' option through that crashes when the ClientHello is built.
group_supported_matches_wire_codes_test() ->
    ?assert(quic_crypto:group_supported(x25519)),
    ?assert(quic_crypto:group_supported(secp256r1)),
    ?assert(quic_crypto:group_supported(secp384r1)),
    ?assertNot(quic_crypto:group_supported(x448)),
    ?assertNot(quic_crypto:group_supported(unknown_group_xyz)).

%%====================================================================
%% `groups' option validation
%%====================================================================

groups_option_test_() ->
    {setup, fun setup/0, fun cleanup/1, [
        fun unusable_group_rejected/0,
        fun empty_groups_rejected/0,
        fun non_list_groups_rejected/0
    ]}.

setup() ->
    {ok, Started} = application:ensure_all_started(quic),
    Started.

cleanup(_Started) ->
    ok.

unusable_group_rejected() ->
    ?assertEqual(
        {error, {unsupported_group, x448}},
        quic:connect(<<"127.0.0.1">>, 4433, #{groups => [x448]}, self())
    ).

%% The head group is the one that gets a key_share, so an empty list
%% has no meaning and used to crash on hd/1 inside the connection.
empty_groups_rejected() ->
    ?assertEqual(
        {error, badarg},
        quic:connect(<<"127.0.0.1">>, 4433, #{groups => []}, self())
    ).

non_list_groups_rejected() ->
    ?assertEqual(
        {error, badarg},
        quic:connect(<<"127.0.0.1">>, 4433, #{groups => x25519}, self())
    ).
