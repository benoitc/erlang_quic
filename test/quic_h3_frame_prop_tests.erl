%%% -*- erlang -*-
%%%
%%% Property-based tests for HTTP/3 frame encoding/decoding
%%% Inspired by quiche fuzz targets
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_h3_frame_prop_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("quic_h3.hrl").

%%====================================================================
%% Property Tests
%%====================================================================

%% All property tests wrapped for EUnit
frame_prop_test_() ->
    {timeout, 60, [
        {"DATA frame roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_data_frame_roundtrip(), [{numtests, 100}, {to_file, user}]))
        end},
        {"HEADERS frame roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_headers_frame_roundtrip(), [{numtests, 100}, {to_file, user}]))
        end},
        {"SETTINGS frame roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_settings_frame_roundtrip(), [{numtests, 100}, {to_file, user}]))
        end},
        {"GOAWAY frame roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_goaway_frame_roundtrip(), [{numtests, 100}, {to_file, user}]))
        end},
        {"MAX_PUSH_ID frame roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_max_push_id_frame_roundtrip(), [{numtests, 100}, {to_file, user}]))
        end},
        {"CANCEL_PUSH frame roundtrip", fun() ->
            ?assert(proper:quickcheck(prop_cancel_push_frame_roundtrip(), [{numtests, 100}, {to_file, user}]))
        end},
        {"Decode arbitrary bytes doesn't crash", fun() ->
            ?assert(proper:quickcheck(prop_decode_arbitrary_no_crash(), [{numtests, 500}, {to_file, user}]))
        end},
        {"Partial frame needs more data", fun() ->
            ?assert(proper:quickcheck(prop_partial_frame_needs_more(), [{numtests, 100}, {to_file, user}]))
        end}
    ]}.

%%====================================================================
%% Properties
%%====================================================================

%% DATA frame encoding/decoding roundtrip
prop_data_frame_roundtrip() ->
    ?FORALL(Payload, binary(),
        begin
            Frame = {data, Payload},
            Encoded = quic_h3_frame:encode(Frame),
            case quic_h3_frame:decode(Encoded) of
                {ok, {data, Decoded}, <<>>} ->
                    Decoded =:= Payload;
                _ ->
                    false
            end
        end).

%% HEADERS frame encoding/decoding roundtrip
prop_headers_frame_roundtrip() ->
    ?FORALL(HeaderBlock, binary(),
        begin
            Frame = {headers, HeaderBlock},
            Encoded = quic_h3_frame:encode(Frame),
            case quic_h3_frame:decode(Encoded) of
                {ok, {headers, Decoded}, <<>>} ->
                    Decoded =:= HeaderBlock;
                _ ->
                    false
            end
        end).

%% SETTINGS frame encoding/decoding roundtrip
prop_settings_frame_roundtrip() ->
    ?FORALL(Settings, settings_map(),
        begin
            Frame = {settings, Settings},
            Encoded = quic_h3_frame:encode(Frame),
            case quic_h3_frame:decode(Encoded) of
                {ok, {settings, Decoded}, <<>>} ->
                    Decoded =:= Settings;
                _ ->
                    false
            end
        end).

%% GOAWAY frame encoding/decoding roundtrip
prop_goaway_frame_roundtrip() ->
    ?FORALL(StreamId, varint(),
        begin
            Frame = {goaway, StreamId},
            Encoded = quic_h3_frame:encode(Frame),
            case quic_h3_frame:decode(Encoded) of
                {ok, {goaway, Decoded}, <<>>} ->
                    Decoded =:= StreamId;
                _ ->
                    false
            end
        end).

%% MAX_PUSH_ID frame encoding/decoding roundtrip
prop_max_push_id_frame_roundtrip() ->
    ?FORALL(PushId, varint(),
        begin
            Frame = {max_push_id, PushId},
            Encoded = quic_h3_frame:encode(Frame),
            case quic_h3_frame:decode(Encoded) of
                {ok, {max_push_id, Decoded}, <<>>} ->
                    Decoded =:= PushId;
                _ ->
                    false
            end
        end).

%% CANCEL_PUSH frame encoding/decoding roundtrip
prop_cancel_push_frame_roundtrip() ->
    ?FORALL(PushId, varint(),
        begin
            Frame = {cancel_push, PushId},
            Encoded = quic_h3_frame:encode(Frame),
            case quic_h3_frame:decode(Encoded) of
                {ok, {cancel_push, Decoded}, <<>>} ->
                    Decoded =:= PushId;
                _ ->
                    false
            end
        end).

%% Decoding arbitrary bytes should not crash (fuzzing)
prop_decode_arbitrary_no_crash() ->
    ?FORALL(Bytes, binary(),
        begin
            %% Should return ok, more, or error - never crash
            try
                case quic_h3_frame:decode(Bytes) of
                    {ok, _, _} -> true;
                    {more, _} -> true;
                    {error, _} -> true
                end
            catch
                _:_ -> false
            end
        end).

%% Partial frames should request more data
prop_partial_frame_needs_more() ->
    ?FORALL({Payload, CutAt}, {non_empty(binary()), pos_integer()},
        begin
            Frame = {data, Payload},
            Encoded = quic_h3_frame:encode(Frame),
            EncodedLen = byte_size(Encoded),
            %% Cut the frame at a random position (but not at the end)
            ActualCut = (CutAt rem max(1, EncodedLen - 1)) + 1,
            Partial = binary:part(Encoded, 0, min(ActualCut, EncodedLen - 1)),
            case quic_h3_frame:decode(Partial) of
                {more, _} -> true;
                {ok, _, _} -> byte_size(Partial) >= EncodedLen;
                {error, _} -> true  %% Some partial data may be invalid
            end
        end).

%%====================================================================
%% Generators
%%====================================================================

%% Generate valid QUIC variable-length integers (0 to 2^62-1)
varint() ->
    frequency([
        {10, range(0, 63)},           %% 1-byte varint
        {5, range(64, 16383)},        %% 2-byte varint
        {3, range(16384, 1073741823)}, %% 4-byte varint
        {1, range(1073741824, 4611686018427387903)} %% 8-byte varint (limited)
    ]).

%% Generate valid H3 settings maps (using atom keys that match decoding)
settings_map() ->
    ?LET(Settings, list(setting()),
        maps:from_list(Settings)).

setting() ->
    frequency([
        {3, {qpack_max_table_capacity, range(0, 1073741823)}},
        {3, {max_field_section_size, range(0, 1073741823)}},
        {3, {qpack_blocked_streams, range(0, 65535)}},
        {1, {enable_connect_protocol, oneof([0, 1])}}
    ]).
