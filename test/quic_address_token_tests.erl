%%% -*- erlang -*-
%%%
%%% Unit tests for RFC 9000 §8.1 retry + NEW_TOKEN tokens.

-module(quic_address_token_tests).

-include_lib("eunit/include/eunit.hrl").

secret() -> <<"a-32-byte-secret-for-token-signs">>.

now_ms() -> erlang:system_time(millisecond).

retry_roundtrip_test() ->
    Addr = {{192, 168, 1, 1}, 51234},
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Token = quic_address_token:encode_retry(secret(), Addr, ODCID, now_ms()),
    {ok, Decoded} = quic_address_token:decode(secret(), Token),
    ?assertEqual(retry, maps:get(kind, Decoded)),
    ?assertEqual(Addr, maps:get(addr, Decoded)),
    ?assertEqual(ODCID, maps:get(odcid, Decoded)),
    ?assertEqual(ok, quic_address_token:validate(Decoded, ODCID, #{})).

new_token_roundtrip_test() ->
    Addr = {{10, 0, 0, 42}, 443},
    Token = quic_address_token:encode_new_token(secret(), Addr, now_ms()),
    {ok, Decoded} = quic_address_token:decode(secret(), Token),
    ?assertEqual(new_token, maps:get(kind, Decoded)),
    ?assertEqual(ok, quic_address_token:validate(Decoded, <<>>, #{})).

ipv6_roundtrip_test() ->
    Addr = {{0, 0, 0, 0, 0, 0, 0, 1}, 4433},
    Token = quic_address_token:encode_new_token(secret(), Addr, now_ms()),
    {ok, Decoded} = quic_address_token:decode(secret(), Token),
    ?assertEqual(Addr, maps:get(addr, Decoded)).

bad_signature_rejected_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    Token = quic_address_token:encode_new_token(secret(), Addr, now_ms()),
    ?assertMatch(
        {error, signature_mismatch},
        quic_address_token:decode(<<"a-different-key-of-32-bytes-long">>, Token)
    ).

expired_token_rejected_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    Long = now_ms() - 60 * 60 * 1000,
    Token = quic_address_token:encode_new_token(secret(), Addr, Long),
    {ok, Decoded} = quic_address_token:decode(secret(), Token),
    ?assertMatch({error, token_expired}, quic_address_token:validate(Decoded, <<>>, #{})).

odcid_mismatch_rejected_test() ->
    Addr = {{127, 0, 0, 1}, 4433},
    Token = quic_address_token:encode_retry(
        secret(), Addr, <<1, 2, 3, 4>>, now_ms()
    ),
    {ok, Decoded} = quic_address_token:decode(secret(), Token),
    ?assertMatch(
        {error, odcid_mismatch},
        quic_address_token:validate(Decoded, <<9, 9, 9, 9>>, #{})
    ).

malformed_token_rejected_test() ->
    ?assertMatch({error, _}, quic_address_token:decode(secret(), <<"too short">>)).
