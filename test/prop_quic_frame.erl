%%% -*- erlang -*-
%%%
%%% PropEr tests for QUIC Frames
%%%

-module(prop_quic_frame).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Generators
%%====================================================================

%% Generate a stream ID (62-bit max, but use smaller for practicality)
stream_id() ->
    range(0, 16#FFFFFFFF).

%% Generate an offset
offset() ->
    range(0, 16#FFFFFFFF).

%% Generate stream data (small for efficiency)
stream_data() ->
    ?LET(Len, range(0, 1000), binary(Len)).

%% Generate error code
error_code() ->
    range(0, 16#FFFF).

%% Generate a PADDING frame (just the atom, not a tuple)
padding_frame() ->
    padding.

%% Generate a PING frame
ping_frame() ->
    ping.

%% Generate an ACK frame
%% Format: {ack, Ranges, AckDelay, ECNCounts}
%% where Ranges = [{LargestAcked, FirstRange} | RestRanges]
%% and ECNCounts = undefined | {ECT0, ECT1, ECNCE}
ack_frame() ->
    ?LET(
        {Largest, Delay, FirstRange, RestRanges},
        {range(0, 1000), range(0, 1000), range(0, 100), list({range(1, 10), range(0, 10)})},
        begin
            Ranges = [{Largest, FirstRange} | RestRanges],
            {ack, Ranges, Delay, undefined}
        end
    ).

%% Generate a CRYPTO frame
crypto_frame() ->
    ?LET(
        {Offset, Data},
        {offset(), stream_data()},
        {crypto, Offset, Data}
    ).

%% Generate a STREAM frame
stream_frame() ->
    ?LET(
        {StreamId, Offset, Data, Fin},
        {stream_id(), offset(), stream_data(), boolean()},
        {stream, StreamId, Offset, Data, Fin}
    ).

%% Generate a RESET_STREAM frame
reset_stream_frame() ->
    ?LET(
        {StreamId, ErrorCode, FinalSize},
        {stream_id(), error_code(), offset()},
        {reset_stream, StreamId, ErrorCode, FinalSize}
    ).

%% Generate a STOP_SENDING frame
stop_sending_frame() ->
    ?LET(
        {StreamId, ErrorCode},
        {stream_id(), error_code()},
        {stop_sending, StreamId, ErrorCode}
    ).

%% Generate a MAX_DATA frame
max_data_frame() ->
    ?LET(
        MaxData,
        range(0, 16#FFFFFFFF),
        {max_data, MaxData}
    ).

%% Generate a MAX_STREAM_DATA frame
max_stream_data_frame() ->
    ?LET(
        {StreamId, MaxData},
        {stream_id(), range(0, 16#FFFFFFFF)},
        {max_stream_data, StreamId, MaxData}
    ).

%% Generate a MAX_STREAMS frame
max_streams_frame() ->
    ?LET(
        {Type, MaxStreams},
        {oneof([bidi, uni]), range(0, 1000)},
        {max_streams, Type, MaxStreams}
    ).

%% Generate a DATA_BLOCKED frame
data_blocked_frame() ->
    ?LET(
        Limit,
        range(0, 16#FFFFFFFF),
        {data_blocked, Limit}
    ).

%% Generate a STREAM_DATA_BLOCKED frame
stream_data_blocked_frame() ->
    ?LET(
        {StreamId, Limit},
        {stream_id(), range(0, 16#FFFFFFFF)},
        {stream_data_blocked, StreamId, Limit}
    ).

%% Generate a STREAMS_BLOCKED frame
streams_blocked_frame() ->
    ?LET(
        {Type, Limit},
        {oneof([bidi, uni]), range(0, 1000)},
        {streams_blocked, Type, Limit}
    ).

%% Generate a NEW_CONNECTION_ID frame
new_connection_id_frame() ->
    ?LET(
        {Seq, Retire, CID, Token},
        {range(0, 100), range(0, 100), binary(8), binary(16)},
        {new_connection_id, Seq, Retire, CID, Token}
    ).

%% Generate a RETIRE_CONNECTION_ID frame
retire_connection_id_frame() ->
    ?LET(
        Seq,
        range(0, 100),
        {retire_connection_id, Seq}
    ).

%% Generate a PATH_CHALLENGE frame
path_challenge_frame() ->
    ?LET(
        Data,
        binary(8),
        {path_challenge, Data}
    ).

%% Generate a PATH_RESPONSE frame
path_response_frame() ->
    ?LET(
        Data,
        binary(8),
        {path_response, Data}
    ).

%% Generate a CONNECTION_CLOSE frame
%% Format: {connection_close, transport|application, ErrorCode, FrameType, Reason}
connection_close_frame() ->
    ?LET(
        {Type, ErrorCode, FrameType, ReasonLen},
        {oneof([transport, application]), error_code(), range(0, 255), range(0, 50)},
        ?LET(
            Reason,
            binary(ReasonLen),
            {connection_close, Type, ErrorCode, FrameType, Reason}
        )
    ).

%% Generate a HANDSHAKE_DONE frame
handshake_done_frame() ->
    handshake_done.

%% Generate any frame
any_frame() ->
    oneof([
        padding_frame(),
        ping_frame(),
        ack_frame(),
        crypto_frame(),
        stream_frame(),
        reset_stream_frame(),
        stop_sending_frame(),
        max_data_frame(),
        max_stream_data_frame(),
        max_streams_frame(),
        data_blocked_frame(),
        stream_data_blocked_frame(),
        streams_blocked_frame(),
        new_connection_id_frame(),
        retire_connection_id_frame(),
        path_challenge_frame(),
        path_response_frame(),
        connection_close_frame(),
        handshake_done_frame()
    ]).

%%====================================================================
%% Properties
%%====================================================================

%% Encoding then decoding returns the original frame
prop_frame_roundtrip() ->
    ?FORALL(
        Frame,
        any_frame(),
        begin
            Encoded = quic_frame:encode(Frame),
            case quic_frame:decode(Encoded) of
                {Decoded, <<>>} ->
                    frames_equal(Frame, Decoded);
                _ ->
                    false
            end
        end
    ).

%% STREAM frame roundtrip
prop_stream_frame_roundtrip() ->
    ?FORALL(
        Frame,
        stream_frame(),
        begin
            Encoded = quic_frame:encode(Frame),
            {Decoded, <<>>} = quic_frame:decode(Encoded),
            frames_equal(Frame, Decoded)
        end
    ).

%% CRYPTO frame roundtrip
prop_crypto_frame_roundtrip() ->
    ?FORALL(
        Frame,
        crypto_frame(),
        begin
            Encoded = quic_frame:encode(Frame),
            {Decoded, <<>>} = quic_frame:decode(Encoded),
            frames_equal(Frame, Decoded)
        end
    ).

%% ACK frame roundtrip
prop_ack_frame_roundtrip() ->
    ?FORALL(
        Frame,
        ack_frame(),
        begin
            Encoded = quic_frame:encode(Frame),
            {Decoded, <<>>} = quic_frame:decode(Encoded),
            frames_equal(Frame, Decoded)
        end
    ).

%% Encoding is deterministic
prop_encode_deterministic() ->
    ?FORALL(
        Frame,
        any_frame(),
        quic_frame:encode(Frame) =:= quic_frame:encode(Frame)
    ).

%% Decoding with extra data preserves the rest
prop_decode_preserves_rest() ->
    ?FORALL(
        {Frame, Rest},
        {any_frame(), binary()},
        begin
            Encoded = quic_frame:encode(Frame),
            {_, Remaining} = quic_frame:decode(<<Encoded/binary, Rest/binary>>),
            Rest =:= Remaining
        end
    ).

%% Multiple frames can be decoded sequentially
prop_decode_multiple() ->
    ?FORALL(
        Frames,
        non_empty(list(any_frame())),
        begin
            Encoded = iolist_to_binary([quic_frame:encode(F) || F <- Frames]),
            case quic_frame:decode_all(Encoded) of
                {ok, Decoded} ->
                    length(Decoded) =:= length(Frames) andalso
                        lists:all(
                            fun({F, D}) -> frames_equal(F, D) end,
                            lists:zip(Frames, Decoded)
                        );
                {error, _} ->
                    false
            end
        end
    ).

%%====================================================================
%% Helpers
%%====================================================================

%% Compare frames (handle different representations)
frames_equal(F1, F2) when F1 =:= F2 -> true;
frames_equal({ack, R1, D1, E1}, {ack, R2, D2, E2}) ->
    R1 =:= R2 andalso D1 =:= D2 andalso E1 =:= E2;
frames_equal({stream, S1, O1, D1, F1}, {stream, S2, O2, D2, F2}) ->
    S1 =:= S2 andalso O1 =:= O2 andalso D1 =:= D2 andalso F1 =:= F2;
frames_equal({crypto, O1, D1}, {crypto, O2, D2}) ->
    O1 =:= O2 andalso D1 =:= D2;
%% For transport close, FrameType is preserved
frames_equal({connection_close, transport, E1, F1, R1}, {connection_close, transport, E2, F2, R2}) ->
    E1 =:= E2 andalso F1 =:= F2 andalso R1 =:= R2;
%% For application close, FrameType is ignored (RFC 9000) - decoded always has undefined
frames_equal(
    {connection_close, application, E1, _, R1}, {connection_close, application, E2, undefined, R2}
) ->
    E1 =:= E2 andalso R1 =:= R2;
frames_equal(_, _) ->
    false.

%%====================================================================
%% EUnit wrapper
%%====================================================================

proper_test_() ->
    {timeout, 120, [
        ?_assert(proper:quickcheck(prop_frame_roundtrip(), [{numtests, 500}, {to_file, user}])),
        ?_assert(
            proper:quickcheck(prop_stream_frame_roundtrip(), [{numtests, 200}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_crypto_frame_roundtrip(), [{numtests, 200}, {to_file, user}])
        ),
        ?_assert(proper:quickcheck(prop_ack_frame_roundtrip(), [{numtests, 200}, {to_file, user}])),
        ?_assert(
            proper:quickcheck(prop_encode_deterministic(), [{numtests, 300}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_decode_preserves_rest(), [{numtests, 300}, {to_file, user}])
        ),
        ?_assert(proper:quickcheck(prop_decode_multiple(), [{numtests, 100}, {to_file, user}]))
    ]}.
