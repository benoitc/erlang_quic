%%% -*- erlang -*-
%%%
%%% Unit tests for server-side Retry packet encoding (RFC 9000 §17.2.5).

-module(quic_retry_packet_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

v1() -> 16#00000001.
v2() -> 16#6b3343cf.

retry_roundtrip_v1_test() ->
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    DCID = <<9, 9, 9, 9>>,
    SCID = <<5, 5, 5, 5, 5, 5, 5, 5>>,
    Token = <<"opaque-retry-token">>,
    Packet = quic_packet:encode_retry(ODCID, DCID, SCID, Token, v1()),
    {ok, Decoded, <<>>} = quic_packet:decode(Packet, 8),
    ?assertMatch(#quic_packet{type = retry}, Decoded),
    ?assertEqual(DCID, Decoded#quic_packet.dcid),
    ?assertEqual(SCID, Decoded#quic_packet.scid),
    ?assertEqual(v1(), Decoded#quic_packet.version).

retry_integrity_tag_verifies_test() ->
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    DCID = <<9, 9, 9, 9>>,
    SCID = <<5, 5, 5, 5, 5, 5, 5, 5>>,
    Token = <<"opaque-retry-token">>,
    Packet = quic_packet:encode_retry(ODCID, DCID, SCID, Token, v1()),
    ?assert(quic_crypto:verify_retry_integrity_tag(ODCID, Packet, v1())).

retry_integrity_rejects_wrong_odcid_test() ->
    ODCID = <<1, 2, 3, 4>>,
    DCID = <<9, 9, 9, 9>>,
    SCID = <<5, 5, 5, 5>>,
    Packet = quic_packet:encode_retry(ODCID, DCID, SCID, <<"tok">>, v1()),
    ?assertNot(
        quic_crypto:verify_retry_integrity_tag(<<9, 8, 7, 6>>, Packet, v1())
    ).

retry_roundtrip_v2_test() ->
    ODCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    DCID = <<9, 9, 9, 9>>,
    SCID = <<5, 5, 5, 5, 5, 5, 5, 5>>,
    Packet = quic_packet:encode_retry(ODCID, DCID, SCID, <<"t">>, v2()),
    ?assert(quic_crypto:verify_retry_integrity_tag(ODCID, Packet, v2())),
    {ok, #quic_packet{type = retry, version = V2, dcid = D, scid = S}, <<>>} =
        quic_packet:decode(Packet, 8),
    ?assertEqual(v2(), V2),
    ?assertEqual(DCID, D),
    ?assertEqual(SCID, S).

retry_empty_token_still_has_valid_tag_test() ->
    ODCID = <<1, 2, 3, 4>>,
    DCID = <<9, 9>>,
    SCID = <<5, 5, 5, 5>>,
    Packet = quic_packet:encode_retry(ODCID, DCID, SCID, <<>>, v1()),
    ?assert(quic_crypto:verify_retry_integrity_tag(ODCID, Packet, v1())).
