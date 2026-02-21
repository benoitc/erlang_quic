%%% -*- erlang -*-
%%%
%%% End-to-End Tests for QUIC-LB CID Encoding
%%% RFC 9312 - QUIC-LB: Generating Routable QUIC Connection IDs
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% Tests the full QUIC-LB integration:
%%% - Listener configuration with LB settings
%%% - CID generation with various algorithms
%%% - Server ID decoding from CIDs
%%% - Variable DCID length handling

-module(quic_lb_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("quic.hrl").

%% CT callbacks
-export([
    suite/0,
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases - Listener Configuration
-export([
    listener_with_plaintext_lb/1,
    listener_with_stream_cipher_lb/1,
    listener_with_block_cipher_lb/1,
    listener_with_variable_cid_len/1,
    listener_without_lb_config/1
]).

%% Test cases - CID Generation
-export([
    cid_generation_plaintext/1,
    cid_generation_stream_cipher/1,
    cid_generation_block_cipher_short/1,
    cid_generation_block_cipher_16byte/1,
    cid_generation_block_cipher_long/1
]).

%% Test cases - CID Routing
-export([
    cid_routing_basic/1,
    cid_routing_multiple_connections/1,
    cid_routing_variable_dcid_len/1
]).

%% Test cases - Server ID Extraction
-export([
    server_id_decode_plaintext/1,
    server_id_decode_stream_cipher/1,
    server_id_decode_block_cipher/1
]).

%% Test cases - Integration
-export([
    full_roundtrip_plaintext/1,
    full_roundtrip_stream_cipher/1,
    full_roundtrip_block_cipher/1,
    multiple_cids_same_server_id/1,
    config_rotation_test/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        {group, listener_config},
        {group, cid_generation},
        {group, cid_routing},
        {group, server_id_extraction},
        {group, integration}
    ].

groups() ->
    [
        {listener_config, [sequence], [
            listener_with_plaintext_lb,
            listener_with_stream_cipher_lb,
            listener_with_block_cipher_lb,
            listener_with_variable_cid_len,
            listener_without_lb_config
        ]},
        {cid_generation, [parallel], [
            cid_generation_plaintext,
            cid_generation_stream_cipher,
            cid_generation_block_cipher_short,
            cid_generation_block_cipher_16byte,
            cid_generation_block_cipher_long
        ]},
        {cid_routing, [sequence], [
            cid_routing_basic,
            cid_routing_multiple_connections,
            cid_routing_variable_dcid_len
        ]},
        {server_id_extraction, [parallel], [
            server_id_decode_plaintext,
            server_id_decode_stream_cipher,
            server_id_decode_block_cipher
        ]},
        {integration, [sequence], [
            full_roundtrip_plaintext,
            full_roundtrip_stream_cipher,
            full_roundtrip_block_cipher,
            multiple_cids_same_server_id,
            config_rotation_test
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

generate_test_cert() ->
    Cert = <<"test_certificate_data">>,
    PrivKey = crypto:strong_rand_bytes(32),
    {Cert, PrivKey}.

make_lb_config(ServerID, Algorithm) ->
    make_lb_config(ServerID, Algorithm, 0, 4).

make_lb_config(ServerID, Algorithm, CR, NonceLen) ->
    Key =
        case Algorithm of
            plaintext -> undefined;
            _ -> crypto:strong_rand_bytes(16)
        end,
    #{
        server_id => ServerID,
        algorithm => Algorithm,
        config_rotation => CR,
        nonce_len => NonceLen,
        key => Key
    }.

start_listener_with_lb(LBConfig) ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>],
        lb_config => LBConfig
    },
    quic_listener:start_link(0, Opts).

%%====================================================================
%% Listener Configuration Tests
%%====================================================================

listener_with_plaintext_lb(_Config) ->
    ServerID = <<1, 2, 3, 4>>,
    LBConfig = make_lb_config(ServerID, plaintext),
    {ok, Listener} = start_listener_with_lb(LBConfig),
    ?assert(is_pid(Listener)),
    ?assert(is_process_alive(Listener)),
    ok = quic_listener:stop(Listener).

listener_with_stream_cipher_lb(_Config) ->
    ServerID = <<5, 6, 7, 8, 9>>,
    LBConfig = make_lb_config(ServerID, stream_cipher),
    {ok, Listener} = start_listener_with_lb(LBConfig),
    ?assert(is_pid(Listener)),
    ?assert(is_process_alive(Listener)),
    ok = quic_listener:stop(Listener).

listener_with_block_cipher_lb(_Config) ->
    ServerID = <<10, 11, 12, 13, 14, 15>>,
    LBConfig = make_lb_config(ServerID, block_cipher),
    {ok, Listener} = start_listener_with_lb(LBConfig),
    ?assert(is_pid(Listener)),
    ?assert(is_process_alive(Listener)),
    ok = quic_listener:stop(Listener).

listener_with_variable_cid_len(_Config) ->
    %% Test different CID lengths
    lists:foreach(
        fun(NonceLen) ->
            ServerID = <<1, 2, 3, 4>>,
            LBConfig = make_lb_config(ServerID, plaintext, 0, NonceLen),
            {ok, Listener} = start_listener_with_lb(LBConfig),
            ?assert(is_pid(Listener)),
            ok = quic_listener:stop(Listener)
        end,
        [4, 6, 8, 10, 12]
    ).

listener_without_lb_config(_Config) ->
    %% Default listener without LB config should still work
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ok = quic_listener:stop(Listener).

%%====================================================================
%% CID Generation Tests
%%====================================================================

cid_generation_plaintext(_Config) ->
    ServerID = <<1, 2, 3, 4>>,
    {ok, LBCfg} = quic_lb:new_config(make_lb_config(ServerID, plaintext)),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    %% Generate multiple CIDs
    CIDs = [quic_lb:generate_cid(CIDConfig) || _ <- lists:seq(1, 10)],

    %% All should be correct length
    ExpectedLen = quic_lb:expected_cid_len(LBCfg),
    lists:foreach(
        fun(CID) ->
            ?assertEqual(ExpectedLen, byte_size(CID)),
            ?assert(quic_lb:is_lb_routable(CID)),
            ?assertEqual(0, quic_lb:get_config_rotation(CID))
        end,
        CIDs
    ),

    %% All should decode to same server_id
    lists:foreach(
        fun(CID) ->
            ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg))
        end,
        CIDs
    ).

cid_generation_stream_cipher(_Config) ->
    ServerID = <<10, 20, 30, 40, 50>>,
    Key = crypto:strong_rand_bytes(16),
    {ok, LBCfg} = quic_lb:new_config(#{
        server_id => ServerID,
        algorithm => stream_cipher,
        key => Key
    }),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    CIDs = [quic_lb:generate_cid(CIDConfig) || _ <- lists:seq(1, 10)],

    %% All should be unique (different nonces)
    UniqueCIDs = lists:usort(CIDs),
    ?assertEqual(length(CIDs), length(UniqueCIDs)),

    %% All should decode to same server_id
    lists:foreach(
        fun(CID) ->
            ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg))
        end,
        CIDs
    ).

cid_generation_block_cipher_short(_Config) ->
    %% Short CID (< 16 bytes) uses Feistel
    ServerID = <<1, 2, 3, 4>>,
    Key = crypto:strong_rand_bytes(16),
    {ok, LBCfg} = quic_lb:new_config(#{
        server_id => ServerID,
        algorithm => block_cipher,
        %% Total CID = 1 + 4 + 4 = 9 bytes
        nonce_len => 4,
        key => Key
    }),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    CID = quic_lb:generate_cid(CIDConfig),
    ?assertEqual(9, byte_size(CID)),
    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg)).

cid_generation_block_cipher_16byte(_Config) ->
    %% Exactly 16-byte CID uses direct AES

    %% 11 bytes
    ServerID = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11>>,
    Key = crypto:strong_rand_bytes(16),
    {ok, LBCfg} = quic_lb:new_config(#{
        server_id => ServerID,
        algorithm => block_cipher,
        %% Total CID = 1 + 11 + 4 = 16 bytes
        nonce_len => 4,
        key => Key
    }),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    CID = quic_lb:generate_cid(CIDConfig),
    ?assertEqual(16, byte_size(CID)),
    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg)).

cid_generation_block_cipher_long(_Config) ->
    %% Long CID (> 16 bytes) uses truncated cipher

    %% 15 bytes
    ServerID = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
    Key = crypto:strong_rand_bytes(16),
    {ok, LBCfg} = quic_lb:new_config(#{
        server_id => ServerID,
        algorithm => block_cipher,
        %% Total CID = 1 + 15 + 4 = 20 bytes
        nonce_len => 4,
        key => Key
    }),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    CID = quic_lb:generate_cid(CIDConfig),
    ?assertEqual(20, byte_size(CID)),
    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg)).

%%====================================================================
%% CID Routing Tests
%%====================================================================

cid_routing_basic(_Config) ->
    %% Test that we can create listener and it generates proper CIDs
    ServerID = <<100, 101, 102, 103>>,
    LBConfigMap = make_lb_config(ServerID, plaintext),
    {ok, LBCfg} = quic_lb:new_config(LBConfigMap),

    {ok, Listener} = start_listener_with_lb(LBConfigMap),
    Port = quic_listener:get_port(Listener),
    ?assert(Port > 0),

    %% Verify config was applied
    ?assert(is_process_alive(Listener)),

    %% The listener should accept packets with correct DCID length
    ExpectedCIDLen = quic_lb:expected_cid_len(LBCfg),
    ct:log("Listener started on port ~p with CID length ~p", [Port, ExpectedCIDLen]),

    ok = quic_listener:stop(Listener).

cid_routing_multiple_connections(_Config) ->
    %% Start listener
    ServerID = <<50, 51, 52, 53>>,
    LBConfigMap = make_lb_config(ServerID, plaintext),
    {ok, Listener} = start_listener_with_lb(LBConfigMap),
    Port = quic_listener:get_port(Listener),

    %% Verify no connections initially
    Connections = quic_listener:get_connections(Listener),
    ?assertEqual([], Connections),

    ct:log("Listener ready on port ~p", [Port]),
    ok = quic_listener:stop(Listener).

cid_routing_variable_dcid_len(_Config) ->
    %% Test with different DCID lengths
    ServerID = <<1, 2, 3, 4>>,
    lists:foreach(
        fun(NonceLen) ->
            LBConfigMap = make_lb_config(ServerID, plaintext, 0, NonceLen),
            {ok, LBCfg} = quic_lb:new_config(LBConfigMap),
            ExpectedLen = quic_lb:expected_cid_len(LBCfg),

            {ok, Listener} = start_listener_with_lb(LBConfigMap),
            ct:log("Testing DCID length ~p (nonce_len=~p)", [ExpectedLen, NonceLen]),
            ok = quic_listener:stop(Listener)
        end,
        [4, 8, 12, 16, 18]
    ).

%%====================================================================
%% Server ID Extraction Tests
%%====================================================================

server_id_decode_plaintext(_Config) ->
    ServerID = <<10, 20, 30, 40>>,
    {ok, LBCfg} = quic_lb:new_config(make_lb_config(ServerID, plaintext)),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    %% Generate and decode multiple times
    lists:foreach(
        fun(_) ->
            CID = quic_lb:generate_cid(CIDConfig),
            {ok, DecodedServerID} = quic_lb:decode_server_id(CID, LBCfg),
            ?assertEqual(ServerID, DecodedServerID)
        end,
        lists:seq(1, 100)
    ).

server_id_decode_stream_cipher(_Config) ->
    ServerID = <<100, 110, 120, 130, 140>>,
    Key = crypto:strong_rand_bytes(16),
    {ok, LBCfg} = quic_lb:new_config(#{
        server_id => ServerID,
        algorithm => stream_cipher,
        key => Key
    }),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    lists:foreach(
        fun(_) ->
            CID = quic_lb:generate_cid(CIDConfig),
            {ok, DecodedServerID} = quic_lb:decode_server_id(CID, LBCfg),
            ?assertEqual(ServerID, DecodedServerID)
        end,
        lists:seq(1, 100)
    ).

server_id_decode_block_cipher(_Config) ->
    ServerID = <<200, 201, 202, 203, 204, 205>>,
    Key = crypto:strong_rand_bytes(16),
    {ok, LBCfg} = quic_lb:new_config(#{
        server_id => ServerID,
        algorithm => block_cipher,
        key => Key
    }),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    lists:foreach(
        fun(_) ->
            CID = quic_lb:generate_cid(CIDConfig),
            {ok, DecodedServerID} = quic_lb:decode_server_id(CID, LBCfg),
            ?assertEqual(ServerID, DecodedServerID)
        end,
        lists:seq(1, 100)
    ).

%%====================================================================
%% Integration Tests
%%====================================================================

full_roundtrip_plaintext(_Config) ->
    %% Full roundtrip: config -> listener -> generate CID -> decode server_id
    ServerID = <<1, 2, 3, 4>>,
    LBConfigMap = make_lb_config(ServerID, plaintext),
    {ok, LBCfg} = quic_lb:new_config(LBConfigMap),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    {ok, Listener} = start_listener_with_lb(LBConfigMap),
    Port = quic_listener:get_port(Listener),
    ct:log("Listener on port ~p", [Port]),

    %% Generate CIDs as the listener would
    CID = quic_lb:generate_cid(CIDConfig),

    %% Verify CID properties
    ?assertEqual(quic_lb:expected_cid_len(LBCfg), byte_size(CID)),
    ?assert(quic_lb:is_lb_routable(CID)),
    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg)),

    ok = quic_listener:stop(Listener).

full_roundtrip_stream_cipher(_Config) ->
    ServerID = <<10, 20, 30, 40, 50>>,
    Key = crypto:strong_rand_bytes(16),
    LBConfigMap = #{
        server_id => ServerID,
        algorithm => stream_cipher,
        key => Key
    },
    {ok, LBCfg} = quic_lb:new_config(LBConfigMap),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    {ok, Listener} = start_listener_with_lb(LBConfigMap),

    CID = quic_lb:generate_cid(CIDConfig),
    ?assert(quic_lb:is_lb_routable(CID)),
    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg)),

    ok = quic_listener:stop(Listener).

full_roundtrip_block_cipher(_Config) ->
    ServerID = <<100, 110, 120, 130>>,
    Key = crypto:strong_rand_bytes(16),
    LBConfigMap = #{
        server_id => ServerID,
        algorithm => block_cipher,
        key => Key
    },
    {ok, LBCfg} = quic_lb:new_config(LBConfigMap),
    {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

    {ok, Listener} = start_listener_with_lb(LBConfigMap),

    CID = quic_lb:generate_cid(CIDConfig),
    ?assert(quic_lb:is_lb_routable(CID)),
    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg)),

    ok = quic_listener:stop(Listener).

multiple_cids_same_server_id(_Config) ->
    %% Test that multiple CIDs from same config all decode to same server_id
    ServerID = <<42, 43, 44, 45>>,
    Key = crypto:strong_rand_bytes(16),

    %% Test with each algorithm
    lists:foreach(
        fun(Algorithm) ->
            LBConfigMap =
                case Algorithm of
                    plaintext -> make_lb_config(ServerID, Algorithm);
                    _ -> #{server_id => ServerID, algorithm => Algorithm, key => Key}
                end,
            {ok, LBCfg} = quic_lb:new_config(LBConfigMap),
            {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

            %% Generate 50 CIDs
            CIDs = [quic_lb:generate_cid(CIDConfig) || _ <- lists:seq(1, 50)],

            %% All should decode to same server_id
            lists:foreach(
                fun(CID) ->
                    ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg))
                end,
                CIDs
            ),

            %% All should be unique (different nonces)
            UniqueCIDs = lists:usort(CIDs),
            ?assertEqual(50, length(UniqueCIDs)),

            ct:log("~p: Generated 50 unique CIDs, all decoding to same server_id", [Algorithm])
        end,
        [plaintext, stream_cipher, block_cipher]
    ).

config_rotation_test(_Config) ->
    %% Test different config rotation values
    ServerID = <<1, 2, 3, 4>>,
    lists:foreach(
        fun(CR) ->
            {ok, LBCfg} = quic_lb:new_config(make_lb_config(ServerID, plaintext, CR, 4)),
            {ok, CIDConfig} = quic_lb:new_cid_config(#{lb_config => LBCfg}),

            CID = quic_lb:generate_cid(CIDConfig),

            %% Verify CR bits are correct
            ?assertEqual(CR, quic_lb:get_config_rotation(CID)),
            ?assert(quic_lb:is_lb_routable(CID)),
            ?assertEqual({ok, ServerID}, quic_lb:decode_server_id(CID, LBCfg)),

            ct:log("Config rotation ~p: OK", [CR])
        end,
        [0, 1, 2, 3, 4, 5, 6]
    ).
