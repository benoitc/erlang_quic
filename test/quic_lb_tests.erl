%%% -*- erlang -*-
%%%
%%% QUIC-LB CID Encoding Tests
%%% RFC 9312 - QUIC-LB: Generating Routable QUIC Connection IDs
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_lb_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Test Setup
%%====================================================================

%% Helper to create a valid LB config
make_lb_config(ServerID, Algorithm) ->
    make_lb_config(ServerID, Algorithm, 0, 4).

make_lb_config(ServerID, Algorithm, CR, NonceLen) ->
    Key =
        case Algorithm of
            plaintext -> undefined;
            _ -> crypto:strong_rand_bytes(16)
        end,
    {ok, Config} = quic_lb:new_config(#{
        server_id => ServerID,
        algorithm => Algorithm,
        config_rotation => CR,
        nonce_len => NonceLen,
        key => Key
    }),
    Config.

make_cid_config(LBConfig) ->
    {ok, Config} = quic_lb:new_cid_config(#{lb_config => LBConfig}),
    Config.

%%====================================================================
%% Configuration Tests
%%====================================================================

config_creation_test_() ->
    [
        {"Create plaintext config", fun() ->
            ServerID = <<1, 2, 3, 4>>,
            Result = quic_lb:new_config(#{server_id => ServerID, algorithm => plaintext}),
            ?assertMatch(
                {ok, #lb_config{
                    server_id = ServerID,
                    server_id_len = 4,
                    algorithm = plaintext
                }},
                Result
            )
        end},

        {"Create encrypted config", fun() ->
            ServerID = <<1, 2, 3, 4, 5>>,
            Key = crypto:strong_rand_bytes(16),
            Result = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => encrypted,
                key => Key
            }),
            ?assertMatch(
                {ok, #lb_config{
                    server_id = ServerID,
                    algorithm = encrypted,
                    key = Key
                }},
                Result
            )
        end},

        {"Pre-draft-22 algorithms are refused", fun() ->
            [
                ?assertEqual(
                    {error, {unsupported_lb_algorithm, Algorithm}},
                    quic_lb:new_config(#{
                        server_id => <<1, 2, 3, 4>>,
                        algorithm => Algorithm,
                        key => crypto:strong_rand_bytes(16)
                    })
                )
             || Algorithm <- [stream_cipher, block_cipher]
            ]
        end},

        {"Unknown algorithm is refused", fun() ->
            ?assertEqual(
                {error, {invalid_algorithm, rot13}},
                quic_lb:new_config(#{server_id => <<1, 2, 3, 4>>, algorithm => rot13})
            )
        end},

        {"Missing server_id fails", fun() ->
            Result = quic_lb:new_config(#{algorithm => plaintext}),
            ?assertMatch({error, missing_server_id}, Result)
        end},

        {"Invalid server_id length fails", fun() ->
            %% 16 bytes is too long (max is 15)
            ServerID = crypto:strong_rand_bytes(16),
            Result = quic_lb:new_config(#{server_id => ServerID}),
            ?assertMatch({error, {invalid_server_id_len, 16}}, Result)
        end},

        {"Invalid config rotation fails", fun() ->
            Result = quic_lb:new_config(#{
                server_id => <<1, 2, 3, 4>>,
                config_rotation => 7
            }),
            ?assertMatch({error, {invalid_config_rotation, 7}}, Result)
        end},

        {"Cipher algorithm without key fails", fun() ->
            Result = quic_lb:new_config(#{
                server_id => <<1, 2, 3, 4>>,
                algorithm => encrypted
            }),
            ?assertMatch({error, {missing_or_invalid_key, encrypted}}, Result)
        end},

        {"Invalid nonce length fails", fun() ->
            Result = quic_lb:new_config(#{
                server_id => <<1, 2, 3, 4>>,
                % min is 4
                nonce_len => 3
            }),
            ?assertMatch({error, {invalid_nonce_len, 3}}, Result)
        end}
    ].

%%====================================================================
%% Length and range rules (draft-ietf-quic-load-balancers-22 3.1, 5.3)
%%====================================================================

lb_lengths(SIDLen, NonceLen) ->
    quic_lb:new_config(#{server_id => binary:copy(<<7>>, SIDLen), nonce_len => NonceLen}).

server_id_and_nonce_lengths_accepted_test_() ->
    [
        ?_assertMatch({ok, #lb_config{}}, lb_lengths(SIDLen, NonceLen))
     || {SIDLen, NonceLen} <- [{1, 4}, {1, 18}, {15, 4}, {10, 9}, {3, 16}]
    ].

server_id_and_nonce_lengths_refused_test_() ->
    [
        ?_assertEqual({error, Reason}, lb_lengths(SIDLen, NonceLen))
     || {SIDLen, NonceLen, Reason} <- [
            {15, 5, {invalid_server_id_nonce_len, 15, 5}},
            {10, 10, {invalid_server_id_nonce_len, 10, 10}},
            {15, 18, {invalid_server_id_nonce_len, 15, 18}},
            {0, 4, {invalid_server_id_len, 0}},
            {16, 4, {invalid_server_id_len, 16}},
            {1, 3, {invalid_nonce_len, 3}},
            {1, 19, {invalid_nonce_len, 19}}
        ]
    ].

non_integer_values_refused_test_() ->
    SID = <<1, 2, 3, 4>>,
    [
        ?_assertEqual(
            {error, {invalid_config_rotation, 1.5}},
            quic_lb:new_config(#{server_id => SID, config_rotation => 1.5})
        ),
        ?_assertEqual(
            {error, {invalid_nonce_len, 4.0}},
            quic_lb:new_config(#{server_id => SID, nonce_len => 4.0})
        ),
        ?_assertEqual(
            {error, {invalid_server_id, not_binary}},
            quic_lb:new_config(#{server_id => [1, 2, 3, 4]})
        ),
        ?_assertEqual({error, {invalid_cid_len, 8.0}}, quic_lb:new_cid_config(#{cid_len => 8.0}))
    ].

%% new_cid_config/1 applies the same rules to an #lb_config{} built by hand.
cid_config_validates_lb_record_test_() ->
    SID = binary:copy(<<7>>, 15),
    Long = #lb_config{server_id = SID, server_id_len = 15, nonce_len = 5},
    [
        ?_assertMatch(
            {ok, #cid_config{cid_len = 20}},
            quic_lb:new_cid_config(#{lb_config => Long#lb_config{nonce_len = 4}})
        ),
        ?_assertEqual(
            {error, {invalid_server_id_nonce_len, 15, 5}},
            quic_lb:new_cid_config(#{lb_config => Long})
        ),
        ?_assertEqual(
            {error, {invalid_server_id_len, undefined}},
            quic_lb:new_cid_config(#{lb_config => #lb_config{server_id = SID}})
        ),
        ?_assertEqual(
            {error, {missing_or_invalid_key, encrypted}},
            quic_lb:new_cid_config(#{
                lb_config => Long#lb_config{nonce_len = 4, algorithm = encrypted}
            })
        ),
        ?_assertEqual(
            {error, {invalid_config_rotation, 7}},
            quic_lb:new_cid_config(#{
                lb_config => Long#lb_config{nonce_len = 4, config_rotation = 7}
            })
        )
    ].

listener_refuses_long_lb_record_test() ->
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    SID = binary:copy(<<7>>, 15),
    LB = #lb_config{server_id = SID, server_id_len = 15, nonce_len = 5},
    ?assertEqual(
        {error, {invalid_lb_config, {invalid_server_id_nonce_len, 15, 5}}},
        quic_listener:start(0, #{cert => Cert, key => Key, alpn => [<<"h3">>], lb_config => LB})
    ).

%% A CID decodes only with the configuration its first three bits name.
decode_checks_config_rotation_test_() ->
    SID = <<1, 2, 3, 4>>,
    LB2 = make_lb_config(SID, plaintext, 2, 4),
    LB3 = make_lb_config(SID, plaintext, 3, 4),
    CID = quic_lb:generate_cid(make_cid_config(LB2)),
    <<_, Rest/binary>> = CID,
    [
        ?_assertEqual({ok, SID}, quic_lb:decode_server_id(CID, LB2)),
        ?_assertEqual({error, config_rotation_mismatch}, quic_lb:decode_server_id(CID, LB3)),
        ?_assertEqual(
            {error, config_rotation_mismatch},
            quic_lb:decode_server_id(<<16#e8, Rest/binary>>, LB2)
        )
    ].

cid_config_creation_test_() ->
    [
        {"Create CID config without LB", fun() ->
            Result = quic_lb:new_cid_config(#{}),
            ?assertMatch(
                {ok, #cid_config{
                    lb_config = undefined,
                    cid_len = 8
                }},
                Result
            )
        end},

        {"Create CID config with LB", fun() ->
            LBConfig = make_lb_config(<<1, 2, 3, 4>>, plaintext),
            Result = quic_lb:new_cid_config(#{lb_config => LBConfig}),
            ExpectedLen = quic_lb:expected_cid_len(LBConfig),
            ?assertMatch(
                {ok, #cid_config{
                    lb_config = LBConfig,
                    cid_len = ExpectedLen
                }},
                Result
            )
        end},

        {"Invalid CID length fails", fun() ->
            Result = quic_lb:new_cid_config(#{cid_len => 21}),
            ?assertMatch({error, {invalid_cid_len, 21}}, Result)
        end}
    ].

%%====================================================================
%% Plaintext Encoding Tests
%%====================================================================

plaintext_encoding_test_() ->
    [
        {"Generate plaintext CID", fun() ->
            ServerID = <<1, 2, 3, 4>>,
            LBConfig = make_lb_config(ServerID, plaintext),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            %% CID should be: 1 (first byte) + 4 (server_id) + 4 (nonce) = 9 bytes
            ?assertEqual(9, byte_size(CID)),
            %% Should be LB routable
            ?assert(quic_lb:is_lb_routable(CID)),
            %% Config rotation should be 0
            ?assertEqual(0, quic_lb:get_config_rotation(CID))
        end},

        {"Decode plaintext CID roundtrip", fun() ->
            ServerID = <<1, 2, 3, 4>>,
            LBConfig = make_lb_config(ServerID, plaintext),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            Result = quic_lb:decode_server_id(CID, LBConfig),
            ?assertEqual({ok, ServerID}, Result)
        end},

        {"Plaintext with config rotation", fun() ->
            ServerID = <<5, 6, 7, 8>>,
            LBConfig = make_lb_config(ServerID, plaintext, 3, 4),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            ?assertEqual(3, quic_lb:get_config_rotation(CID)),
            ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
        end},

        {"Plaintext with longer nonce", fun() ->
            ServerID = <<1, 2, 3>>,
            LBConfig = make_lb_config(ServerID, plaintext, 0, 8),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            %% CID should be: 1 + 3 + 8 = 12 bytes
            ?assertEqual(12, byte_size(CID)),
            ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
        end},

        {"Plaintext with max server ID", fun() ->
            % max length
            ServerID = crypto:strong_rand_bytes(15),
            LBConfig = make_lb_config(ServerID, plaintext, 0, 4),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            %% CID should be: 1 + 15 + 4 = 20 bytes (max CID length)
            ?assertEqual(20, byte_size(CID)),
            ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
        end}
    ].

%%====================================================================
%% draft-ietf-quic-load-balancers-22 Appendix B.1 vectors
%%====================================================================

%% {CR, ServerID, Nonce, CID}. The second B.1 row prints the nonce
%% without its leading zero (9 hex digits) and the first octet as "20a";
%% the row here is that vector with the nonce read as 0x03487d970b.
plaintext_vectors() ->
    [
        {0, <<16#c4605e:24>>, <<16#4504cc4f:32>>, <<16#07c4605e4504cc4f:64>>},
        {1, <<16#350d28b420:40>>, <<16#03487d970b:40>>, <<16#2a350d28b42003487d970b:88>>}
    ].

plaintext_vector_encode_test_() ->
    [
        ?_assertEqual(CID, quic_lb:generate_cid(plaintext_cid_config(CR, SID, Nonce), Nonce))
     || {CR, SID, Nonce, CID} <- plaintext_vectors()
    ].

plaintext_vector_decode_test_() ->
    [
        ?_assertEqual(
            {ok, SID},
            quic_lb:decode_server_id(CID, plaintext_lb_config(CR, SID, byte_size(Nonce)))
        )
     || {CR, SID, Nonce, CID} <- plaintext_vectors()
    ].

plaintext_lb_config(CR, SID, NonceLen) ->
    {ok, LB} = quic_lb:new_config(#{
        server_id => SID, algorithm => plaintext, config_rotation => CR, nonce_len => NonceLen
    }),
    LB.

plaintext_cid_config(CR, SID, Nonce) ->
    make_cid_config(plaintext_lb_config(CR, SID, byte_size(Nonce))).

%%====================================================================
%% draft-ietf-quic-load-balancers-22 Section 5.4 encryption
%%====================================================================

-define(B2_KEY, <<16#8f95f09245765f80256934e50c66207f:128>>).

%% {CR, ServerID, Nonce, CID} from Appendix B.2. The draft prints the
%% cr_bits 3 CID with first octet 0x12 (config rotation 0); 0x72 is the
%% first octet for config rotation 3 and 18 octets, the rest matches.
encrypted_vectors() ->
    [
        {0, <<16#ed793a:24>>, <<16#ee080dbf:32>>, <<16#0720b1d07b359d3c:64>>},
        {1, <<16#ed793a51d49b8f5fab65:80>>, <<16#ee080dbf48:40>>, <<
            16#2fcc381bc74cb4fbad2823a3d1f8fed2:128
        >>},
        {2, <<16#ed793a51d49b8f5f:64>>, <<16#ee080dbf48c0d1e5:64>>, <<
            16#504dd2d05a7b0de9b2b9907afb5ecf8cc3:136
        >>},
        {3, <<16#ed793a51d49b8f5fab:72>>, <<16#ee080dbf48c0d1e55d:72>>, <<
            16#725779c9cc86beb3a3a4a3ca96fce4bfe0cdbc:152
        >>}
    ].

encrypted_lb_config(CR, SID, NonceLen, Key) ->
    {ok, LB} = quic_lb:new_config(#{
        server_id => SID,
        algorithm => encrypted,
        config_rotation => CR,
        nonce_len => NonceLen,
        key => Key
    }),
    LB.

encrypted_vector_encode_test_() ->
    [
        ?_assertEqual(
            CID,
            quic_lb:generate_cid(
                make_cid_config(encrypted_lb_config(CR, SID, byte_size(Nonce), ?B2_KEY)), Nonce
            )
        )
     || {CR, SID, Nonce, CID} <- encrypted_vectors()
    ].

encrypted_vector_decode_test_() ->
    [
        ?_assertEqual(
            {ok, SID},
            quic_lb:decode_server_id(CID, encrypted_lb_config(CR, SID, byte_size(Nonce), ?B2_KEY))
        )
     || {CR, SID, Nonce, CID} <- encrypted_vectors()
    ].

%% Section 5.4.2.4 worked example: 7 octets, split by nibble.
encryption_example_test() ->
    Key = <<16#fdf726a9893ec05c0632d3956680baf0:128>>,
    LB = encrypted_lb_config(0, <<16#31441a:24>>, 4, Key),
    CID = quic_lb:generate_cid(make_cid_config(LB), <<16#9c69c275:32>>),
    ?assertEqual(<<16#0767947d29be054a:64>>, CID),
    ?assertEqual({ok, <<16#31441a:24>>}, quic_lb:decode_server_id(CID, LB)).

%% The single pass is plain AES-128-ECB over the server ID and nonce.
encrypted_single_pass_is_aes_ecb_test() ->
    Key = crypto:strong_rand_bytes(16),
    SID = crypto:strong_rand_bytes(6),
    Nonce = crypto:strong_rand_bytes(10),
    CID = quic_lb:generate_cid(make_cid_config(encrypted_lb_config(0, SID, 10, Key)), Nonce),
    Block = crypto:crypto_one_time(aes_128_ecb, Key, <<SID/binary, Nonce/binary>>, true),
    ?assertEqual(<<16, Block/binary>>, CID).

%% Every server ID and nonce length the draft allows, both decode paths.
encrypted_roundtrip_all_lengths_test() ->
    Key = crypto:strong_rand_bytes(16),
    [
        begin
            SID = crypto:strong_rand_bytes(SIDLen),
            LB = encrypted_lb_config(5, SID, NonceLen, Key),
            CID = quic_lb:generate_cid(make_cid_config(LB)),
            ?assertEqual(1 + SIDLen + NonceLen, byte_size(CID)),
            ?assertEqual(5, quic_lb:get_config_rotation(CID)),
            ?assertNotEqual(SID, binary:part(CID, 1, SIDLen)),
            ?assertEqual({ok, SID}, quic_lb:decode_server_id(CID, LB))
        end
     || SIDLen <- lists:seq(1, 15), NonceLen <- lists:seq(4, 19 - SIDLen)
    ],
    ok.

%% Octets a server appends after the nonce do not change the server ID.
encrypted_decode_ignores_server_use_octets_test() ->
    {CR, SID, Nonce, CID} = lists:nth(2, encrypted_vectors()),
    LB = encrypted_lb_config(CR, SID, byte_size(Nonce), ?B2_KEY),
    ?assertEqual({ok, SID}, quic_lb:decode_server_id(<<CID/binary, 1, 2, 3>>, LB)),
    ?assertEqual({error, cid_too_short}, quic_lb:decode_server_id(binary:part(CID, 0, 15), LB)).

encrypted_preserves_config_rotation_test() ->
    Key = crypto:strong_rand_bytes(16),
    [
        begin
            LB = encrypted_lb_config(CR, <<1, 2, 3>>, 4, Key),
            CID = quic_lb:generate_cid(make_cid_config(LB)),
            ?assertEqual(CR, quic_lb:get_config_rotation(CID)),
            ?assertEqual({ok, <<1, 2, 3>>}, quic_lb:decode_server_id(CID, LB))
        end
     || CR <- lists:seq(0, 6)
    ],
    ok.

%%====================================================================
%% Helper Function Tests
%%====================================================================

helper_function_test_() ->
    [
        {"expected_cid_len calculation", fun() ->
            LBConfig = make_lb_config(<<1, 2, 3, 4>>, plaintext, 0, 4),
            ?assertEqual(9, quic_lb:expected_cid_len(LBConfig)),

            LBConfig2 = make_lb_config(<<1, 2, 3, 4, 5, 6, 7, 8>>, plaintext, 0, 8),
            ?assertEqual(17, quic_lb:expected_cid_len(LBConfig2))
        end},

        {"is_lb_routable checks", fun() ->
            LBConfig = make_lb_config(<<1, 2, 3, 4>>, plaintext),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            ?assert(quic_lb:is_lb_routable(CID)),

            %% Random CID should be unroutable (CR bits likely 7)
            RandomCID = crypto:strong_rand_bytes(8),
            %% Can't guarantee unroutable, but check function works
            _ = quic_lb:is_lb_routable(RandomCID)
        end},

        {"get_config_rotation from CID", fun() ->
            %% Test all valid CR values
            lists:foreach(
                fun(CR) ->
                    LBConfig = make_lb_config(<<1, 2, 3, 4>>, plaintext, CR, 4),
                    CIDConfig = make_cid_config(LBConfig),
                    CID = quic_lb:generate_cid(CIDConfig),
                    ?assertEqual(CR, quic_lb:get_config_rotation(CID))
                end,
                [0, 1, 2, 3, 4, 5, 6]
            )
        end},

        {"Empty CID returns unroutable", fun() ->
            ?assertEqual(?LB_CR_UNROUTABLE, quic_lb:get_config_rotation(<<>>))
        end}
    ].

%%====================================================================
%% CID Generation Without LB Config Tests
%%====================================================================

no_lb_config_test_() ->
    [
        {"Generate random CID without LB config", fun() ->
            {ok, CIDConfig} = quic_lb:new_cid_config(#{}),
            CID = quic_lb:generate_cid(CIDConfig),
            ?assertEqual(8, byte_size(CID))
        end},

        {"Generate random CID with custom length", fun() ->
            {ok, CIDConfig} = quic_lb:new_cid_config(#{cid_len => 12}),
            CID = quic_lb:generate_cid(CIDConfig),
            ?assertEqual(12, byte_size(CID))
        end}
    ].

%%====================================================================
%% Explicit Nonce Tests
%%====================================================================

explicit_nonce_test_() ->
    [
        {"Generate CID with explicit nonce", fun() ->
            ServerID = <<1, 2, 3, 4>>,
            LBConfig = make_lb_config(ServerID, plaintext, 0, 4),
            CIDConfig = make_cid_config(LBConfig),
            Nonce = <<16#DE, 16#AD, 16#BE, 16#EF>>,
            CID = quic_lb:generate_cid(CIDConfig, Nonce),
            %% Verify the nonce is in the CID
            <<_FirstByte, _ServerIDBytes:4/binary, NonceInCID:4/binary>> = CID,
            ?assertEqual(Nonce, NonceInCID)
        end},

        {"Nonce is padded if too short", fun() ->
            ServerID = <<1, 2, 3, 4>>,
            LBConfig = make_lb_config(ServerID, plaintext, 0, 8),
            CIDConfig = make_cid_config(LBConfig),
            % 2 bytes, need 8
            ShortNonce = <<16#AB, 16#CD>>,
            CID = quic_lb:generate_cid(CIDConfig, ShortNonce),
            % 1 + 4 + 8
            ?assertEqual(13, byte_size(CID)),
            %% Should still decode correctly
            ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
        end},

        {"Nonce is truncated if too long", fun() ->
            ServerID = <<1, 2, 3, 4>>,
            LBConfig = make_lb_config(ServerID, plaintext, 0, 4),
            CIDConfig = make_cid_config(LBConfig),
            % 8 bytes, need 4
            LongNonce = <<1, 2, 3, 4, 5, 6, 7, 8>>,
            CID = quic_lb:generate_cid(CIDConfig, LongNonce),
            % 1 + 4 + 4
            ?assertEqual(9, byte_size(CID)),
            %% Verify first 4 bytes of nonce are used
            <<_FirstByte, _ServerIDBytes:4/binary, NonceInCID:4/binary>> = CID,
            ?assertEqual(<<1, 2, 3, 4>>, NonceInCID)
        end}
    ].

%%====================================================================
%% Listener Integration Tests
%%====================================================================

listener_integration_test_() ->
    {foreach,
        fun() ->
            %% Setup: ensure crypto is started
            application:ensure_all_started(crypto),
            ok
        end,
        fun(_) ->
            %% Cleanup
            ok
        end,
        [
            {"Listener starts with plaintext LB config", fun() ->
                {Cert, PrivKey} = generate_test_cert(),
                ServerID = <<1, 2, 3, 4>>,
                LBConfig = #{
                    server_id => ServerID,
                    algorithm => plaintext
                },
                Opts = #{
                    cert => Cert,
                    key => PrivKey,
                    alpn => [<<"h3">>],
                    lb_config => LBConfig
                },
                {ok, Listener} = quic_listener:start_link(0, Opts),
                ?assert(is_pid(Listener)),
                Port = quic_listener:get_port(Listener),
                ?assert(Port > 0),
                ok = quic_listener:stop(Listener)
            end},

            {"Listener starts with encrypted LB config", fun() ->
                {Cert, PrivKey} = generate_test_cert(),
                ServerID = <<5, 6, 7, 8, 9>>,
                Key = crypto:strong_rand_bytes(16),
                LBConfig = #{
                    server_id => ServerID,
                    algorithm => encrypted,
                    key => Key
                },
                Opts = #{
                    cert => Cert,
                    key => PrivKey,
                    alpn => [<<"h3">>],
                    lb_config => LBConfig
                },
                {ok, Listener} = quic_listener:start_link(0, Opts),
                ?assert(is_pid(Listener)),
                ok = quic_listener:stop(Listener)
            end},

            {"Listener with custom CID length", fun() ->
                {Cert, PrivKey} = generate_test_cert(),
                ServerID = <<1, 2, 3, 4>>,
                LBConfig = #{
                    server_id => ServerID,
                    algorithm => plaintext,
                    %% Longer nonce = longer CID
                    nonce_len => 12
                },
                Opts = #{
                    cert => Cert,
                    key => PrivKey,
                    alpn => [<<"h3">>],
                    lb_config => LBConfig
                },
                {ok, Listener} = quic_listener:start_link(0, Opts),
                ?assert(is_pid(Listener)),
                ok = quic_listener:stop(Listener)
            end},

            {"Listener without LB config uses default CID length", fun() ->
                {Cert, PrivKey} = generate_test_cert(),
                Opts = #{
                    cert => Cert,
                    key => PrivKey,
                    alpn => [<<"h3">>]
                },
                {ok, Listener} = quic_listener:start_link(0, Opts),
                ?assert(is_pid(Listener)),
                ok = quic_listener:stop(Listener)
            end}
        ]}.

%% An lb_config that cannot be used stops the listener from starting
%% instead of leaving it on random CIDs the load balancer cannot route.
bad_lb_config() ->
    #{server_id => <<1, 2, 3, 4>>, nonce_len => 3}.

listener_refuses_invalid_lb_config_test() ->
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    ?assertEqual(
        {error, {invalid_lb_config, {invalid_nonce_len, 3}}},
        quic_listener:start(0, #{
            cert => Cert, key => Key, alpn => [<<"h3">>], lb_config => bad_lb_config()
        })
    ).

listener_refuses_non_map_lb_config_test() ->
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    ?assertEqual(
        {error, {invalid_lb_config, badarg}},
        quic_listener:start(0, #{
            cert => Cert, key => Key, alpn => [<<"h3">>], lb_config => [{server_id, <<1>>}]
        })
    ).

start_server_refuses_invalid_lb_config_test() ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    Name = list_to_atom("lb_config_" ++ integer_to_list(erlang:unique_integer([positive]))),
    Result = quic:start_server(Name, 0, #{
        cert => Cert, key => Key, alpn => [<<"h3">>], lb_config => bad_lb_config()
    }),
    case Result of
        {ok, _} -> quic:stop_server(Name);
        _ -> ok
    end,
    ?assertEqual({error, {invalid_lb_config, {invalid_nonce_len, 3}}}, Result).

generate_test_cert() ->
    Cert = <<"test_certificate_data">>,
    PrivKey = crypto:strong_rand_bytes(32),
    {Cert, PrivKey}.

%%====================================================================
%% Multiple Roundtrip Tests (Stability)
%%====================================================================

stability_test_() ->
    [
        {"Multiple plaintext roundtrips", fun() ->
            ServerID = <<100, 101, 102, 103>>,
            LBConfig = make_lb_config(ServerID, plaintext),
            CIDConfig = make_cid_config(LBConfig),
            lists:foreach(
                fun(_) ->
                    CID = quic_lb:generate_cid(CIDConfig),
                    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
                end,
                lists:seq(1, 100)
            )
        end},

        {"Multiple encrypted roundtrips", fun() ->
            ServerID = <<200, 201, 202, 203, 204>>,
            LBConfig = encrypted_lb_config(0, ServerID, 4, crypto:strong_rand_bytes(16)),
            CIDConfig = make_cid_config(LBConfig),
            lists:foreach(
                fun(_) ->
                    CID = quic_lb:generate_cid(CIDConfig),
                    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
                end,
                lists:seq(1, 100)
            )
        end}
    ].
