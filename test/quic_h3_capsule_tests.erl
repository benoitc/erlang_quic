%%% -*- erlang -*-
%%%
%%% Unit tests for RFC 9297 §3.2 Capsule Protocol codec.

-module(quic_h3_capsule_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic_h3.hrl").

roundtrip_zero_type_empty_value_test() ->
    Encoded = iolist_to_binary(quic_h3_capsule:encode(?H3_CAPSULE_DATAGRAM, <<>>)),
    ?assertEqual({ok, {?H3_CAPSULE_DATAGRAM, <<>>, <<>>}}, quic_h3_capsule:decode(Encoded)).

roundtrip_legacy_datagram_type_test() ->
    Value = <<"hello">>,
    Encoded = iolist_to_binary(
        quic_h3_capsule:encode(?H3_CAPSULE_LEGACY_DATAGRAM, Value)
    ),
    ?assertEqual(
        {ok, {?H3_CAPSULE_LEGACY_DATAGRAM, Value, <<>>}},
        quic_h3_capsule:decode(Encoded)
    ).

roundtrip_1k_payload_test() ->
    Value = crypto:strong_rand_bytes(1024),
    Encoded = iolist_to_binary(quic_h3_capsule:encode(42, Value)),
    ?assertEqual({ok, {42, Value, <<>>}}, quic_h3_capsule:decode(Encoded)).

decode_with_trailing_bytes_preserves_rest_test() ->
    Encoded = iolist_to_binary(quic_h3_capsule:encode(7, <<"abc">>)),
    ?assertEqual(
        {ok, {7, <<"abc">>, <<"trailer">>}},
        quic_h3_capsule:decode(<<Encoded/binary, "trailer">>)
    ).

decode_partial_buffer_returns_more_test() ->
    Full = iolist_to_binary(quic_h3_capsule:encode(0, <<"0123456789">>)),
    Partial = binary:part(Full, 0, byte_size(Full) - 3),
    ?assertMatch({more, _}, quic_h3_capsule:decode(Partial)).

decode_empty_buffer_returns_more_test() ->
    ?assertEqual({more, 1}, quic_h3_capsule:decode(<<>>)).
