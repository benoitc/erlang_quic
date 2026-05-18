%%% -*- erlang -*-
%%% Unit tests for TLS 1.3 external PSK support (RFC 8446 §4.2.11).

-module(quic_psk_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(IDENTITY, <<"test-identity">>).
-define(SECRET, <<"this-is-a-32-byte-test-secret!!!">>).

%%====================================================================
%% Helpers
%%====================================================================

build_external_ch(Modes) ->
    Opts = #{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        transport_params => #{},
        external_psk => {?IDENTITY, ?SECRET, Modes}
    },
    {Msg, _PrivKey, _Random} = quic_tls:build_client_hello(Opts),
    Msg.

%% Strip the 4-byte handshake-message header → body bytes.
ch_body(Msg) ->
    <<_MsgType:8, _Len:24, Body/binary>> = Msg,
    Body.

%%====================================================================
%% psk_offer_from_opts: client-side input validation
%%====================================================================

bad_opts_psk_conflict_test() ->
    %% session_ticket + external_psk together must raise loud.
    Ticket = {session_ticket, <<"node">>, <<>>, 0, 0, <<>>, <<>>, 0, 0, aes_128_gcm, <<>>},
    ?assertError(
        {bad_opts, psk_conflict},
        quic_tls:build_client_hello(#{
            session_ticket => Ticket,
            external_psk => {?IDENTITY, ?SECRET}
        })
    ).

external_psk_unsupported_mode_test() ->
    ?assertError(
        {bad_opts, {unsupported_psk_modes, [foobar]}},
        quic_tls:build_client_hello(#{
            external_psk => {?IDENTITY, ?SECRET, [psk_dhe_ke, foobar]}
        })
    ).

external_psk_bad_shape_test() ->
    %% Non-binary identity → bad_opts.
    ?assertError(
        {bad_opts, {external_psk, _}},
        quic_tls:build_client_hello(#{external_psk => {not_a_binary, ?SECRET}})
    ).

%%====================================================================
%% ClientHello round-trip
%%====================================================================

build_and_parse_external_psk_ch_test() ->
    Msg = build_external_ch([psk_dhe_ke]),
    {ok, Map} = quic_tls:parse_client_hello(ch_body(Msg)),
    PSK = maps:get(pre_shared_key, Map),
    ?assertMatch(
        #{identities := [{?IDENTITY, 0}]},
        PSK
    ),
    [Binder] = maps:get(binders, PSK),
    ?assertEqual(32, byte_size(Binder)),
    %% psk_key_exchange_modes echoed
    ?assertEqual([psk_dhe_ke], maps:get(psk_key_exchange_modes, Map)).

psk_ke_only_offered_test() ->
    Msg = build_external_ch([psk_ke]),
    {ok, Map} = quic_tls:parse_client_hello(ch_body(Msg)),
    ?assertEqual([psk_ke], maps:get(psk_key_exchange_modes, Map)).

both_modes_offered_test() ->
    Msg = build_external_ch([psk_dhe_ke, psk_ke]),
    {ok, Map} = quic_tls:parse_client_hello(ch_body(Msg)),
    ?assertEqual([psk_dhe_ke, psk_ke], maps:get(psk_key_exchange_modes, Map)).

%%====================================================================
%% parse_extensions_ordered: order + uniqueness
%%====================================================================

parse_extensions_ordered_preserves_order_test() ->
    Ext1 = <<?EXT_SUPPORTED_VERSIONS:16, 2:16, ?TLS_VERSION_1_3:16>>,
    Ext2 = <<?EXT_ALPN:16, 7:16, 5:16, 2, "h2", 1, "h">>,
    Blob = <<Ext1/binary, Ext2/binary>>,
    {ok, [E1, E2]} = quic_tls:parse_extensions_ordered(Blob),
    ?assertMatch({?EXT_SUPPORTED_VERSIONS, _, 0, _}, E1),
    ?assertMatch({?EXT_ALPN, _, ByteOff, _} when ByteOff > 0, E2).

parse_extensions_ordered_rejects_duplicate_test() ->
    Ext = <<?EXT_ALPN:16, 0:16>>,
    Blob = <<Ext/binary, Ext/binary>>,
    ?assertEqual(
        {error, {duplicate_extension, ?EXT_ALPN}},
        quic_tls:parse_extensions_ordered(Blob)
    ).

%%====================================================================
%% select_psk: identity lookup, mode intersection, binder verify
%%====================================================================

select_psk_returns_ok_for_matching_psk_test() ->
    Msg = build_external_ch([psk_dhe_ke]),
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Msg)),
    Config = #{psks => #{?IDENTITY => ?SECRET}, psk_callback => undefined},
    {ok, Sel} = quic_tls:select_psk(CHMap, Msg, Config, [psk_dhe_ke, psk_ke]),
    ?assertEqual(?IDENTITY, maps:get(identity, Sel)),
    ?assertEqual(?SECRET, maps:get(secret, Sel)),
    ?assertEqual(psk_dhe_ke, maps:get(mode, Sel)),
    ?assertEqual(0, maps:get(identity_idx, Sel)).

select_psk_callback_wins_over_map_test() ->
    %% Callback returns a DIFFERENT secret for the same identity. If the
    %% callback wins, the binder won't match the one client sent, so we
    %% expect {error, bad_binder}.
    Msg = build_external_ch([psk_dhe_ke]),
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Msg)),
    Config = #{
        psk_callback => fun(?IDENTITY) -> {ok, <<"wrong-secret">>} end,
        psks => #{?IDENTITY => ?SECRET}
    },
    ?assertEqual(
        {error, bad_binder},
        quic_tls:select_psk(CHMap, Msg, Config, [psk_dhe_ke])
    ).

select_psk_callback_falls_back_to_map_on_not_found_test() ->
    Msg = build_external_ch([psk_dhe_ke]),
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Msg)),
    Config = #{
        psk_callback => fun(_) -> not_found end,
        psks => #{?IDENTITY => ?SECRET}
    },
    {ok, _} = quic_tls:select_psk(CHMap, Msg, Config, [psk_dhe_ke]).

select_psk_callback_crash_falls_back_to_map_test() ->
    Msg = build_external_ch([psk_dhe_ke]),
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Msg)),
    Config = #{
        psk_callback => fun(_) -> error(boom) end,
        psks => #{?IDENTITY => ?SECRET}
    },
    %% Should not crash; falls through to the map.
    {ok, _} = quic_tls:select_psk(CHMap, Msg, Config, [psk_dhe_ke]).

select_psk_unknown_identity_returns_none_test() ->
    Msg = build_external_ch([psk_dhe_ke]),
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Msg)),
    Config = #{
        psk_callback => undefined,
        psks => #{<<"other-identity">> => <<"some-secret">>}
    },
    ?assertEqual(none, quic_tls:select_psk(CHMap, Msg, Config, [psk_dhe_ke])).

select_psk_mode_intersection_empty_returns_none_test() ->
    Msg = build_external_ch([psk_ke]),
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Msg)),
    Config = #{psks => #{?IDENTITY => ?SECRET}, psk_callback => undefined},
    %% Client offered only psk_ke; server only allows psk_dhe_ke.
    ?assertEqual(none, quic_tls:select_psk(CHMap, Msg, Config, [psk_dhe_ke])).

select_psk_picks_first_compatible_mode_test() ->
    Msg = build_external_ch([psk_ke, psk_dhe_ke]),
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Msg)),
    Config = #{psks => #{?IDENTITY => ?SECRET}, psk_callback => undefined},
    %% Server accepts both; client preference is psk_ke first.
    {ok, Sel} = quic_tls:select_psk(CHMap, Msg, Config, [psk_ke, psk_dhe_ke]),
    ?assertEqual(psk_ke, maps:get(mode, Sel)).

select_psk_bad_binder_test() ->
    %% Mutate one byte of the binder section to corrupt it.
    Msg = build_external_ch([psk_dhe_ke]),
    %% The binder is the last 32 bytes of the message; flip one bit.
    Size = byte_size(Msg),
    <<Head:(Size - 1)/binary, Last:8>> = Msg,
    Corrupted = <<Head/binary, (Last bxor 1):8>>,
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Corrupted)),
    Config = #{psks => #{?IDENTITY => ?SECRET}, psk_callback => undefined},
    ?assertEqual(
        {error, bad_binder},
        quic_tls:select_psk(CHMap, Corrupted, Config, [psk_dhe_ke])
    ).

select_psk_no_pre_shared_key_returns_none_test() ->
    %% Build a vanilla ClientHello with no external_psk.
    Opts = #{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        transport_params => #{}
    },
    {Msg, _, _} = quic_tls:build_client_hello(Opts),
    {ok, CHMap} = quic_tls:parse_client_hello(ch_body(Msg)),
    Config = #{psks => #{?IDENTITY => ?SECRET}, psk_callback => undefined},
    ?assertEqual(none, quic_tls:select_psk(CHMap, Msg, Config, [psk_dhe_ke])).

%%====================================================================
%% ServerHello PSK echo + key_share omission
%%====================================================================

server_hello_with_psk_includes_pre_shared_key_test() ->
    {Msg, _PrivKey} = quic_tls:build_server_hello(#{
        selected_psk_identity => 0,
        selected_psk_mode => psk_dhe_ke
    }),
    %% Parse it back and verify pre_shared_key extension carries idx 0.
    <<_:8, _:24, Body/binary>> = Msg,
    {ok, Map} = quic_tls:parse_server_hello(Body),
    ?assertEqual(0, maps:get(selected_psk_identity, Map)).

server_hello_psk_ke_omits_key_share_test() ->
    {Msg, _PrivKey} = quic_tls:build_server_hello(#{
        selected_psk_identity => 0,
        selected_psk_mode => psk_ke
    }),
    <<_:8, _:24, Body/binary>> = Msg,
    {ok, Map} = quic_tls:parse_server_hello(Body),
    ?assertEqual(undefined, maps:get(public_key, Map)),
    ?assertEqual(0, maps:get(selected_psk_identity, Map)).

server_hello_psk_dhe_ke_includes_key_share_test() ->
    {Msg, _PrivKey} = quic_tls:build_server_hello(#{
        selected_psk_identity => 0,
        selected_psk_mode => psk_dhe_ke
    }),
    <<_:8, _:24, Body/binary>> = Msg,
    {ok, Map} = quic_tls:parse_server_hello(Body),
    PubKey = maps:get(public_key, Map),
    ?assertEqual(32, byte_size(PubKey)),
    ?assertEqual(0, maps:get(selected_psk_identity, Map)).

%%====================================================================
%% Key-schedule helper: derive_handshake_secret_psk_only
%%====================================================================

handshake_secret_psk_only_differs_from_dhe_test() ->
    EarlySecret = quic_crypto:derive_early_secret(aes_128_gcm, ?SECRET),
    DHE = crypto:strong_rand_bytes(32),
    HsDhe = quic_crypto:derive_handshake_secret(aes_128_gcm, EarlySecret, DHE),
    HsPskOnly = quic_crypto:derive_handshake_secret_psk_only(aes_128_gcm, EarlySecret),
    ?assertNotEqual(HsDhe, HsPskOnly).

handshake_secret_psk_only_deterministic_test() ->
    EarlySecret = quic_crypto:derive_early_secret(aes_128_gcm, ?SECRET),
    H1 = quic_crypto:derive_handshake_secret_psk_only(aes_128_gcm, EarlySecret),
    H2 = quic_crypto:derive_handshake_secret_psk_only(aes_128_gcm, EarlySecret),
    ?assertEqual(H1, H2),
    ?assertEqual(32, byte_size(H1)).
