%%% -*- erlang -*-
%%%
%%% PropEr tests for RFC 9221 DATAGRAM frame encoding.
%%%
%%% Mirrors the pattern of prop_quic_frame but covers only the two
%%% datagram shapes: 0x30 (no length field, spans to end of packet)
%%% and 0x31 (length-prefixed, can be coalesced with other frames).

-module(prop_quic_datagram).

-include_lib("proper/include/proper.hrl").

%%====================================================================
%% Generators
%%====================================================================

%% RFC 9221 caps the payload at whatever the peer advertised (up to
%% 65535 in practice). We exercise up to 4 KiB to keep shrinking fast
%% while still covering varint boundaries at 63/16383.
datagram_payload() ->
    ?LET(Len, range(0, 4096), binary(Len)).

%%====================================================================
%% Properties
%%====================================================================

%% datagram_with_length frames (type 0x31) must roundtrip through a
%% decode when another frame follows, because the length field is what
%% allows the decoder to find the frame boundary.
prop_datagram_with_length_roundtrip() ->
    ?FORALL(
        Payload,
        datagram_payload(),
        begin
            Frame = {datagram_with_length, Payload},
            Encoded = iolist_to_binary(quic_frame:encode(Frame)),
            {{datagram_with_length, Decoded}, <<>>} = quic_frame:decode(Encoded),
            Decoded =:= Payload
        end
    ).

%% datagram frames without a length field (type 0x30) always run to the
%% end of the packet, so decoding the encoded bytes alone must yield
%% exactly the input.
prop_datagram_no_length_roundtrip() ->
    ?FORALL(
        Payload,
        datagram_payload(),
        begin
            Frame = {datagram, Payload},
            Encoded = iolist_to_binary(quic_frame:encode(Frame)),
            {{datagram, Decoded}, <<>>} = quic_frame:decode(Encoded),
            Decoded =:= Payload
        end
    ).

%% A length-prefixed DATAGRAM concatenated with a PING byte must still
%% decode cleanly — the length field is what makes coalescing possible.
prop_datagram_with_length_coalesces() ->
    ?FORALL(
        Payload,
        datagram_payload(),
        begin
            Frame = {datagram_with_length, Payload},
            Encoded = iolist_to_binary(quic_frame:encode(Frame)),
            %% PING is single-byte 0x01.
            Trailer = <<16#01>>,
            Combined = <<Encoded/binary, Trailer/binary>>,
            {{datagram_with_length, Decoded}, Rest} = quic_frame:decode(Combined),
            Decoded =:= Payload andalso Rest =:= Trailer
        end
    ).
