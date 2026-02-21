%%% -*- erlang -*-
%%%
%%% PropEr tests for QUIC Variable-Length Integers
%%%

-module(prop_quic_varint).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Generators
%%====================================================================

%% Generate valid varint values (0 to 2^62 - 1)
varint_value() ->
    ?LET(
        Bits,
        range(0, 62),
        ?LET(V, range(0, (1 bsl Bits) - 1), V)
    ).

%% Generate small varints (1 byte, 0-63)
small_varint() ->
    range(0, 63).

%% Generate medium varints (2 bytes, 64-16383)
medium_varint() ->
    range(64, 16383).

%% Generate large varints (4 bytes, 16384-1073741823)
large_varint() ->
    range(16384, 1073741823).

%% Generate extra large varints (8 bytes)
xlarge_varint() ->
    range(1073741824, 4611686018427387903).

%%====================================================================
%% Properties
%%====================================================================

%% Encoding then decoding returns the original value
prop_roundtrip() ->
    ?FORALL(
        V,
        varint_value(),
        begin
            Encoded = quic_varint:encode(V),
            {Decoded, <<>>} = quic_varint:decode(Encoded),
            V =:= Decoded
        end
    ).

%% Encoding produces correct length based on value
prop_encoded_length() ->
    ?FORALL(
        V,
        varint_value(),
        begin
            Encoded = quic_varint:encode(V),
            ExpectedLen = expected_length(V),
            byte_size(Encoded) =:= ExpectedLen
        end
    ).

%% Small values use 1 byte
prop_small_uses_one_byte() ->
    ?FORALL(
        V,
        small_varint(),
        byte_size(quic_varint:encode(V)) =:= 1
    ).

%% Medium values use 2 bytes
prop_medium_uses_two_bytes() ->
    ?FORALL(
        V,
        medium_varint(),
        byte_size(quic_varint:encode(V)) =:= 2
    ).

%% Large values use 4 bytes
prop_large_uses_four_bytes() ->
    ?FORALL(
        V,
        large_varint(),
        byte_size(quic_varint:encode(V)) =:= 4
    ).

%% Extra large values use 8 bytes
prop_xlarge_uses_eight_bytes() ->
    ?FORALL(
        V,
        xlarge_varint(),
        byte_size(quic_varint:encode(V)) =:= 8
    ).

%% Decoding with extra data preserves the rest
prop_decode_preserves_rest() ->
    ?FORALL(
        {V, Rest},
        {varint_value(), binary()},
        begin
            Encoded = quic_varint:encode(V),
            {Decoded, Remaining} = quic_varint:decode(<<Encoded/binary, Rest/binary>>),
            V =:= Decoded andalso Rest =:= Remaining
        end
    ).

%% Encoding is deterministic
prop_encode_deterministic() ->
    ?FORALL(
        V,
        varint_value(),
        quic_varint:encode(V) =:= quic_varint:encode(V)
    ).

%% First two bits indicate length
prop_length_prefix() ->
    ?FORALL(
        V,
        varint_value(),
        begin
            <<Prefix:2, _/bits>> = quic_varint:encode(V),
            ExpectedPrefix =
                case expected_length(V) of
                    1 -> 0;
                    2 -> 1;
                    4 -> 2;
                    8 -> 3
                end,
            Prefix =:= ExpectedPrefix
        end
    ).

%%====================================================================
%% Helpers
%%====================================================================

expected_length(V) when V =< 63 -> 1;
expected_length(V) when V =< 16383 -> 2;
expected_length(V) when V =< 1073741823 -> 4;
expected_length(_) -> 8.

%%====================================================================
%% EUnit wrapper
%%====================================================================

proper_test_() ->
    {timeout, 60, [
        ?_assert(proper:quickcheck(prop_roundtrip(), [{numtests, 1000}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_encoded_length(), [{numtests, 1000}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_small_uses_one_byte(), [{numtests, 100}, {to_file, user}])),
        ?_assert(
            proper:quickcheck(prop_medium_uses_two_bytes(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_large_uses_four_bytes(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_xlarge_uses_eight_bytes(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_decode_preserves_rest(), [{numtests, 500}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_encode_deterministic(), [{numtests, 500}, {to_file, user}])
        ),
        ?_assert(proper:quickcheck(prop_length_prefix(), [{numtests, 500}, {to_file, user}]))
    ]}.
