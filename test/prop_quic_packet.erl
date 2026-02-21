%%% -*- erlang -*-
%%%
%%% PropEr tests for QUIC Packets
%%%

-module(prop_quic_packet).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Generators
%%====================================================================

%% Connection ID (1-20 bytes, using 8 for simplicity)
connection_id() ->
    binary(8).

%% Packet number (0-2^32)
packet_number() ->
    range(0, 16#FFFFFFFF).

%% Version
version() ->
    oneof([?QUIC_VERSION_1, ?QUIC_VERSION_2]).

%% Payload
payload() ->
    ?LET(Len, range(1, 500), binary(Len)).

%% Long header packet type
long_packet_type() ->
    oneof([initial, handshake, zero_rtt]).

%%====================================================================
%% Properties
%%====================================================================

%% Long header encode/decode roundtrip
prop_long_header_roundtrip() ->
    ?FORALL(
        {Type, Ver, DCID, SCID, PN, Payload},
        {
            long_packet_type(),
            version(),
            connection_id(),
            connection_id(),
            packet_number(),
            payload()
        },
        begin
            Opts =
                case Type of
                    initial -> #{token => <<>>, payload => Payload, pn => PN};
                    _ -> #{payload => Payload, pn => PN}
                end,
            Encoded = quic_packet:encode_long(Type, Ver, DCID, SCID, Opts),
            case quic_packet:decode(Encoded, 8) of
                {ok, Packet, <<>>} ->
                    Packet#quic_packet.type =:= Type andalso
                        Packet#quic_packet.version =:= Ver andalso
                        Packet#quic_packet.dcid =:= DCID andalso
                        Packet#quic_packet.scid =:= SCID;
                _ ->
                    false
            end
        end
    ).

%% Short header encode/decode roundtrip
prop_short_header_roundtrip() ->
    ?FORALL(
        {DCID, PN, Payload, SpinBit},
        {connection_id(), packet_number(), payload(), boolean()},
        begin
            Encoded = quic_packet:encode_short(DCID, PN, Payload, SpinBit),
            case quic_packet:decode(Encoded, 8) of
                {ok, Packet, <<>>} ->
                    Packet#quic_packet.type =:= one_rtt andalso
                        Packet#quic_packet.dcid =:= DCID;
                _ ->
                    false
            end
        end
    ).

%% Encoding is deterministic
prop_encode_deterministic() ->
    ?FORALL(
        {DCID, SCID, PN, Payload},
        {connection_id(), connection_id(), packet_number(), payload()},
        begin
            Opts = #{payload => Payload, pn => PN},
            E1 = quic_packet:encode_long(handshake, ?QUIC_VERSION_1, DCID, SCID, Opts),
            E2 = quic_packet:encode_long(handshake, ?QUIC_VERSION_1, DCID, SCID, Opts),
            E1 =:= E2
        end
    ).

%% First byte indicates long vs short header
prop_header_form_bit() ->
    ?FORALL(
        {DCID, SCID, PN, Payload},
        {connection_id(), connection_id(), packet_number(), payload()},
        begin
            LongOpts = #{payload => Payload, pn => PN},
            LongEncoded = quic_packet:encode_long(handshake, ?QUIC_VERSION_1, DCID, SCID, LongOpts),
            ShortEncoded = quic_packet:encode_short(DCID, PN, Payload, false),
            <<LongFirst, _/binary>> = LongEncoded,
            <<ShortFirst, _/binary>> = ShortEncoded,
            %% Long header has form bit (0x80) set
            (LongFirst band 16#80) =:= 16#80 andalso
                %% Short header has form bit clear
                (ShortFirst band 16#80) =:= 16#00
        end
    ).

%% DCID length is correctly encoded in long headers
prop_dcid_length_encoded() ->
    ?FORALL(
        {Type, DCID, SCID, Payload},
        {long_packet_type(), connection_id(), connection_id(), payload()},
        begin
            Opts =
                case Type of
                    initial -> #{token => <<>>, payload => Payload, pn => 0};
                    _ -> #{payload => Payload, pn => 0}
                end,
            Encoded = quic_packet:encode_long(Type, ?QUIC_VERSION_1, DCID, SCID, Opts),
            %% DCID length is at byte 5
            <<_:5/binary, DCIDLen, _/binary>> = Encoded,
            DCIDLen =:= byte_size(DCID)
        end
    ).

%%====================================================================
%% EUnit wrapper
%%====================================================================

proper_test_() ->
    {timeout, 120, [
        ?_assert(
            proper:quickcheck(prop_long_header_roundtrip(), [{numtests, 300}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_short_header_roundtrip(), [{numtests, 300}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_encode_deterministic(), [{numtests, 200}, {to_file, user}])
        ),
        ?_assert(proper:quickcheck(prop_header_form_bit(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_dcid_length_encoded(), [{numtests, 200}, {to_file, user}]))
    ]}.
