%%% -*- erlang -*-
%%%
%%% Unit tests for stateless-reset token derivation (RFC 9000 §10.3.2).

-module(quic_stateless_reset_tests).

-include_lib("eunit/include/eunit.hrl").

secret() ->
    <<"a-32-byte-secret-for-hmac-tests!">>.

deterministic_token_for_same_cid_test() ->
    S = quic_connection_test_support:state_with_secret(secret()),
    CID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    T1 = quic_connection:generate_stateless_reset_token(CID, S),
    T2 = quic_connection:generate_stateless_reset_token(CID, S),
    ?assertEqual(T1, T2),
    ?assertEqual(16, byte_size(T1)).

different_cids_produce_different_tokens_test() ->
    S = quic_connection_test_support:state_with_secret(secret()),
    T1 = quic_connection:generate_stateless_reset_token(<<1, 2, 3, 4>>, S),
    T2 = quic_connection:generate_stateless_reset_token(<<5, 6, 7, 8>>, S),
    ?assertNotEqual(T1, T2).

different_secrets_produce_different_tokens_test() ->
    CID = <<1, 2, 3, 4>>,
    T1 = quic_connection:generate_stateless_reset_token(
        CID, quic_connection_test_support:state_with_secret(secret())
    ),
    OtherSecret = <<"another-32-byte-secret-for-tests">>,
    T2 = quic_connection:generate_stateless_reset_token(
        CID, quic_connection_test_support:state_with_secret(OtherSecret)
    ),
    ?assertNotEqual(T1, T2).

undefined_secret_still_yields_16_random_bytes_test() ->
    S = quic_connection_test_support:state_with_secret(undefined),
    T = quic_connection:generate_stateless_reset_token(<<1, 2, 3>>, S),
    ?assertEqual(16, byte_size(T)).

%% RFC 9000 Section 10.3: a reset answering a packet of 43 bytes or less
%% is one byte shorter than it.
small_trigger_gets_reset_one_byte_shorter_test() ->
    Token = crypto:strong_rand_bytes(16),
    [
        ?assertEqual(Size - 1, byte_size(quic_listener:build_stateless_reset(Token, Size)))
     || Size <- lists:seq(22, 43), _ <- lists:seq(1, 20)
    ].

large_trigger_gets_smaller_reset_test() ->
    Token = crypto:strong_rand_bytes(16),
    [
        ?assert(byte_size(quic_listener:build_stateless_reset(Token, Size)) < Size)
     || Size <- [44, 100, 1200], _ <- lists:seq(1, 20)
    ].
