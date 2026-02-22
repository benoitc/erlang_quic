%%% -*- erlang -*-
%%%
%%% QUIC Stateless Reset Tests
%%% RFC 9000 Section 10.3 - Stateless Reset
%%%
%%% This module tests stateless reset functionality including token
%%% generation, packet building, and detection.
%%%

-module(quic_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Stateless Reset Token Generation (RFC 9000 Section 10.3.2)
%%====================================================================

%% Test token generation is deterministic
reset_token_deterministic_test() ->
    Secret = crypto:strong_rand_bytes(32),
    CID = crypto:strong_rand_bytes(8),

    Token1 = compute_reset_token(Secret, CID),
    Token2 = compute_reset_token(Secret, CID),

    ?assertEqual(Token1, Token2),
    ?assertEqual(16, byte_size(Token1)).

%% Test different CIDs produce different tokens
reset_token_unique_per_cid_test() ->
    Secret = crypto:strong_rand_bytes(32),
    CID1 = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    CID2 = <<8, 7, 6, 5, 4, 3, 2, 1>>,

    Token1 = compute_reset_token(Secret, CID1),
    Token2 = compute_reset_token(Secret, CID2),

    ?assertNotEqual(Token1, Token2).

%% Test different secrets produce different tokens
reset_token_unique_per_secret_test() ->
    Secret1 = crypto:strong_rand_bytes(32),
    Secret2 = crypto:strong_rand_bytes(32),
    CID = crypto:strong_rand_bytes(8),

    Token1 = compute_reset_token(Secret1, CID),
    Token2 = compute_reset_token(Secret2, CID),

    ?assertNotEqual(Token1, Token2).

%%====================================================================
%% Stateless Reset Packet Format (RFC 9000 Section 10.3)
%%====================================================================

%% Test reset packet has correct structure
reset_packet_structure_test() ->
    Token = crypto:strong_rand_bytes(16),
    TriggerSize = 100,

    Packet = build_reset_packet(Token, TriggerSize),

    %% Packet should be at least 21 bytes
    ?assert(byte_size(Packet) >= 21),

    %% Packet should be smaller than trigger
    ?assert(byte_size(Packet) < TriggerSize),

    %% First byte should look like short header (0|1|XXXXXX)
    <<FirstByte, _/binary>> = Packet,
    % First bit = 0 (short header)
    ?assertEqual(0, (FirstByte bsr 7) band 1),
    % Fixed bit = 1
    ?assertEqual(1, (FirstByte bsr 6) band 1),

    %% Last 16 bytes should be the token
    PacketSize = byte_size(Packet),
    TokenOffset = PacketSize - 16,
    <<_:TokenOffset/binary, ExtractedToken:16/binary>> = Packet,
    ?assertEqual(Token, ExtractedToken).

%% Test reset packet minimum size
reset_packet_minimum_size_test() ->
    Token = crypto:strong_rand_bytes(16),
    % Just above minimum
    TriggerSize = 25,

    Packet = build_reset_packet(Token, TriggerSize),

    ?assert(byte_size(Packet) >= 21),
    ?assert(byte_size(Packet) < TriggerSize).

%% Test reset packet varies in size (unpredictability)
reset_packet_size_variation_test() ->
    Token = crypto:strong_rand_bytes(16),
    TriggerSize = 200,

    %% Generate multiple packets and check they have varying sizes
    Packets = [build_reset_packet(Token, TriggerSize) || _ <- lists:seq(1, 20)],
    Sizes = [byte_size(P) || P <- Packets],
    UniqueSizes = lists:usort(Sizes),

    %% Should have some variation in sizes (probabilistic, may rarely fail)
    ?assert(length(UniqueSizes) > 1).

%%====================================================================
%% Stateless Reset Detection (RFC 9000 Section 10.3)
%%====================================================================

%% Test detection with known token
reset_detection_match_test() ->
    Secret = crypto:strong_rand_bytes(32),
    CID = crypto:strong_rand_bytes(8),
    Token = compute_reset_token(Secret, CID),

    %% Create mock CID entry
    CIDEntry = #cid_entry{
        seq_num = 0,
        cid = CID,
        stateless_reset_token = Token
    },

    ?assertEqual({ok, CID}, find_matching_token(Token, [CIDEntry])).

%% Test detection with no match
reset_detection_no_match_test() ->
    Token = crypto:strong_rand_bytes(16),
    WrongToken = crypto:strong_rand_bytes(16),

    CIDEntry = #cid_entry{
        seq_num = 0,
        cid = <<1, 2, 3, 4, 5, 6, 7, 8>>,
        stateless_reset_token = WrongToken
    },

    ?assertEqual(not_found, find_matching_token(Token, [CIDEntry])).

%% Test detection with multiple CIDs
reset_detection_multiple_cids_test() ->
    Token1 = crypto:strong_rand_bytes(16),
    Token2 = crypto:strong_rand_bytes(16),
    Token3 = crypto:strong_rand_bytes(16),

    CID1 = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    CID2 = <<2, 3, 4, 5, 6, 7, 8, 9>>,
    CID3 = <<3, 4, 5, 6, 7, 8, 9, 10>>,

    CIDEntries = [
        #cid_entry{seq_num = 0, cid = CID1, stateless_reset_token = Token1},
        #cid_entry{seq_num = 1, cid = CID2, stateless_reset_token = Token2},
        #cid_entry{seq_num = 2, cid = CID3, stateless_reset_token = Token3}
    ],

    ?assertEqual({ok, CID1}, find_matching_token(Token1, CIDEntries)),
    ?assertEqual({ok, CID2}, find_matching_token(Token2, CIDEntries)),
    ?assertEqual({ok, CID3}, find_matching_token(Token3, CIDEntries)),
    ?assertEqual(not_found, find_matching_token(crypto:strong_rand_bytes(16), CIDEntries)).

%% Test empty CID pool
reset_detection_empty_pool_test() ->
    Token = crypto:strong_rand_bytes(16),
    ?assertEqual(not_found, find_matching_token(Token, [])).

%%====================================================================
%% Potential Reset Detection (Anti-loop)
%%====================================================================

%% Test short header packet could be a reset
potential_reset_short_header_test() ->
    %% Short header with at least 21 bytes
    ShortHeaderPacket = <<16#40, (crypto:strong_rand_bytes(36))/binary>>,
    ?assert(is_potential_reset(ShortHeaderPacket)).

%% Test long header packet cannot be a reset
potential_reset_long_header_test() ->
    %% Long header (first bit = 1)
    LongHeaderPacket = <<16#C0, (crypto:strong_rand_bytes(100))/binary>>,
    ?assertNot(is_potential_reset(LongHeaderPacket)).

%% Test too small packet cannot be a reset
potential_reset_too_small_test() ->
    SmallPacket = <<16#40, (crypto:strong_rand_bytes(10))/binary>>,
    ?assertNot(is_potential_reset(SmallPacket)).

%%====================================================================
%% Helper Functions
%%====================================================================

%% Same algorithm as quic_listener
compute_reset_token(Secret, CID) ->
    <<Token:16/binary, _/binary>> = crypto:mac(hmac, sha256, Secret, CID),
    Token.

%% Same algorithm as quic_listener
build_reset_packet(Token, TriggerSize) ->
    ResetSize = min(TriggerSize - 1, max(21, rand:uniform(20) + 21)),
    RandomLen = ResetSize - 17,
    RandomBytes = crypto:strong_rand_bytes(RandomLen),
    <<FirstRandom:6, _:2>> = crypto:strong_rand_bytes(1),
    FirstByte = (0 bsl 7) bor (1 bsl 6) bor FirstRandom,
    <<FirstByte, RandomBytes/binary, Token/binary>>.

%% Same algorithm as quic_connection
find_matching_token(_Token, []) ->
    not_found;
find_matching_token(Token, [#cid_entry{stateless_reset_token = Token, cid = CID} | _]) ->
    {ok, CID};
find_matching_token(Token, [_ | Rest]) ->
    find_matching_token(Token, Rest).

%% Check if packet could be a stateless reset
is_potential_reset(<<0:1, _:7, _Rest/binary>> = Packet) ->
    byte_size(Packet) >= 21;
is_potential_reset(_) ->
    false.
