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

        {"Create stream cipher config", fun() ->
            ServerID = <<1, 2, 3, 4, 5>>,
            Key = crypto:strong_rand_bytes(16),
            Result = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => stream_cipher,
                key => Key
            }),
            ?assertMatch(
                {ok, #lb_config{
                    server_id = ServerID,
                    algorithm = stream_cipher,
                    key = Key
                }},
                Result
            )
        end},

        {"Create block cipher config", fun() ->
            ServerID = <<1, 2, 3, 4, 5, 6>>,
            Key = crypto:strong_rand_bytes(16),
            Result = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => block_cipher,
                key => Key
            }),
            ?assertMatch(
                {ok, #lb_config{
                    server_id = ServerID,
                    algorithm = block_cipher,
                    key = Key
                }},
                Result
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
                algorithm => stream_cipher
            }),
            ?assertMatch({error, {missing_or_invalid_key, stream_cipher}}, Result)
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
%% Stream Cipher Encoding Tests
%%====================================================================

stream_cipher_encoding_test_() ->
    [
        {"Generate stream cipher CID", fun() ->
            ServerID = <<1, 2, 3, 4>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => stream_cipher,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            ?assertEqual(9, byte_size(CID)),
            ?assert(quic_lb:is_lb_routable(CID))
        end},

        {"Decode stream cipher CID roundtrip", fun() ->
            ServerID = <<10, 20, 30, 40, 50>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => stream_cipher,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            Result = quic_lb:decode_server_id(CID, LBConfig),
            ?assertEqual({ok, ServerID}, Result)
        end},

        {"Stream cipher with different nonce lengths", fun() ->
            ServerID = <<1, 2, 3, 4>>,
            Key = crypto:strong_rand_bytes(16),
            lists:foreach(
                fun(NonceLen) ->
                    {ok, LBConfig} = quic_lb:new_config(#{
                        server_id => ServerID,
                        algorithm => stream_cipher,
                        nonce_len => NonceLen,
                        key => Key
                    }),
                    CIDConfig = make_cid_config(LBConfig),
                    CID = quic_lb:generate_cid(CIDConfig),
                    ExpectedLen = 1 + 4 + NonceLen,
                    ?assertEqual(ExpectedLen, byte_size(CID)),
                    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
                end,
                [4, 8, 12, 16, 18]
            )
        end},

        {"Stream cipher preserves config rotation", fun() ->
            ServerID = <<1, 2, 3>>,
            Key = crypto:strong_rand_bytes(16),
            lists:foreach(
                fun(CR) ->
                    {ok, LBConfig} = quic_lb:new_config(#{
                        server_id => ServerID,
                        algorithm => stream_cipher,
                        config_rotation => CR,
                        key => Key
                    }),
                    CIDConfig = make_cid_config(LBConfig),
                    CID = quic_lb:generate_cid(CIDConfig),
                    ?assertEqual(CR, quic_lb:get_config_rotation(CID)),
                    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
                end,
                [0, 1, 2, 3, 4, 5, 6]
            )
        end}
    ].

%%====================================================================
%% Block Cipher Encoding Tests
%%====================================================================

block_cipher_encoding_test_() ->
    [
        {"Generate block cipher CID (short - Feistel)", fun() ->
            %% CID < 16 bytes uses Feistel network
            ServerID = <<1, 2, 3, 4>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => block_cipher,
                nonce_len => 4,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            %% 1 + 4 + 4 = 9 bytes (< 16, uses Feistel)
            ?assertEqual(9, byte_size(CID)),
            ?assert(quic_lb:is_lb_routable(CID))
        end},

        {"Decode block cipher CID roundtrip (short - Feistel)", fun() ->
            ServerID = <<10, 20, 30, 40>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => block_cipher,
                nonce_len => 4,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            Result = quic_lb:decode_server_id(CID, LBConfig),
            ?assertEqual({ok, ServerID}, Result)
        end},

        {"Generate block cipher CID (exact 16 bytes - direct AES)", fun() ->
            %% CID = 16 bytes uses direct AES-ECB

            % 11 bytes
            ServerID = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => block_cipher,
                % 1 + 11 + 4 = 16 bytes
                nonce_len => 4,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            ?assertEqual(16, byte_size(CID)),
            ?assert(quic_lb:is_lb_routable(CID))
        end},

        {"Decode block cipher CID roundtrip (exact 16 bytes)", fun() ->
            % 11 bytes
            ServerID = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => block_cipher,
                nonce_len => 4,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            Result = quic_lb:decode_server_id(CID, LBConfig),
            ?assertEqual({ok, ServerID}, Result)
        end},

        {"Generate block cipher CID (long - truncated)", fun() ->
            %% CID > 16 bytes uses truncated cipher

            % 15 bytes
            ServerID = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => block_cipher,
                % 1 + 15 + 4 = 20 bytes
                nonce_len => 4,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            ?assertEqual(20, byte_size(CID)),
            ?assert(quic_lb:is_lb_routable(CID))
        end},

        {"Decode block cipher CID roundtrip (long - truncated)", fun() ->
            ServerID = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => block_cipher,
                nonce_len => 4,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            CID = quic_lb:generate_cid(CIDConfig),
            Result = quic_lb:decode_server_id(CID, LBConfig),
            ?assertEqual({ok, ServerID}, Result)
        end},

        {"Block cipher with various sizes", fun() ->
            Key = crypto:strong_rand_bytes(16),
            %% Test different server_id sizes to exercise all code paths
            lists:foreach(
                fun(ServerIDLen) ->
                    ServerID = crypto:strong_rand_bytes(ServerIDLen),
                    {ok, LBConfig} = quic_lb:new_config(#{
                        server_id => ServerID,
                        algorithm => block_cipher,
                        nonce_len => 4,
                        key => Key
                    }),
                    CIDConfig = make_cid_config(LBConfig),
                    CID = quic_lb:generate_cid(CIDConfig),
                    Result = quic_lb:decode_server_id(CID, LBConfig),
                    ?assertEqual({ok, ServerID}, Result)
                end,
                lists:seq(1, 15)
            )
        end}
    ].

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

            {"Listener starts with stream cipher LB config", fun() ->
                {Cert, PrivKey} = generate_test_cert(),
                ServerID = <<5, 6, 7, 8, 9>>,
                Key = crypto:strong_rand_bytes(16),
                LBConfig = #{
                    server_id => ServerID,
                    algorithm => stream_cipher,
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

            {"Listener starts with block cipher LB config", fun() ->
                {Cert, PrivKey} = generate_test_cert(),
                ServerID = <<10, 11, 12, 13, 14, 15>>,
                Key = crypto:strong_rand_bytes(16),
                LBConfig = #{
                    server_id => ServerID,
                    algorithm => block_cipher,
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

        {"Multiple stream cipher roundtrips", fun() ->
            ServerID = <<200, 201, 202, 203, 204>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => stream_cipher,
                key => Key
            }),
            CIDConfig = make_cid_config(LBConfig),
            lists:foreach(
                fun(_) ->
                    CID = quic_lb:generate_cid(CIDConfig),
                    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBConfig))
                end,
                lists:seq(1, 100)
            )
        end},

        {"Multiple block cipher roundtrips", fun() ->
            ServerID = <<150, 151, 152, 153, 154, 155>>,
            Key = crypto:strong_rand_bytes(16),
            {ok, LBConfig} = quic_lb:new_config(#{
                server_id => ServerID,
                algorithm => block_cipher,
                key => Key
            }),
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
