%%% -*- erlang -*-
%%%
%%% The QUIC ACK frequency extension (draft-ietf-quic-ack-frequency-14):
%%% the min_ack_delay transport parameter, the ACK_FREQUENCY and
%%% IMMEDIATE_ACK frames, and where a peer may send them.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_ack_frequency_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%%====================================================================
%% Frames (Sections 4 and 5)
%%====================================================================

ack_frequency_wire_format_test() ->
    %% Type 0xaf is a two-byte varint, then four varint fields.
    ?assertEqual(
        <<16#40, 16#af, 7, 10, 16#40, 16#c8, 3>>,
        quic_frame:encode({ack_frequency, 7, 10, 200, 3})
    ).

ack_frequency_roundtrip_test() ->
    Max = 16#3FFFFFFFFFFFFFFF,
    lists:foreach(
        fun(Frame) ->
            ?assertEqual({Frame, <<>>}, quic_frame:decode(quic_frame:encode(Frame)))
        end,
        [
            {ack_frequency, 0, 0, 1000, 0},
            {ack_frequency, 1, 1, 25000, 1},
            {ack_frequency, Max, Max, Max, Max}
        ]
    ).

immediate_ack_wire_format_test() ->
    ?assertEqual(<<16#1f>>, quic_frame:encode(immediate_ack)),
    ?assertEqual({immediate_ack, <<1>>}, quic_frame:decode(<<16#1f, 1>>)).

frames_decode_in_a_packet_test() ->
    Payload = iolist_to_binary([
        quic_frame:encode(immediate_ack),
        quic_frame:encode({ack_frequency, 2, 4, 5000, 3}),
        quic_frame:encode(ping)
    ]),
    ?assertEqual(
        {ok, [immediate_ack, {ack_frequency, 2, 4, 5000, 3}, ping]},
        quic_frame:decode_all(Payload)
    ).

truncated_ack_frequency_is_malformed_test() ->
    Full = quic_frame:encode({ack_frequency, 1, 2, 3000, 1}),
    lists:foreach(
        fun(Len) ->
            ?assertMatch(
                {error, {malformed, _}},
                quic_connection:decode_frame(binary:part(Full, 0, Len))
            )
        end,
        lists:seq(2, byte_size(Full) - 1)
    ).

ack_frequency_is_ack_eliciting_test() ->
    ?assert(quic_ack:is_ack_eliciting_frame({ack_frequency, 0, 1, 1000, 1})),
    ?assert(quic_ack:is_ack_eliciting_frame(immediate_ack)).

%%====================================================================
%% min_ack_delay transport parameter (Section 3)
%%====================================================================

min_ack_delay_roundtrip_test() ->
    Bin = quic_tls:encode_transport_params(#{min_ack_delay => 1000}),
    %% 0xff04de1b is an eight-byte varint id.
    ?assertEqual(<<16#c0, 0, 0, 0, 16#ff, 16#04, 16#de, 16#1b, 2, 16#43, 16#e8>>, Bin),
    ?assertEqual({ok, #{min_ack_delay => 1000}}, quic_tls:decode_transport_params(Bin)).

min_ack_delay_up_to_max_ack_delay_test() ->
    ?assertMatch(
        {ok, #{min_ack_delay := 10000}},
        decode(#{min_ack_delay => 10000, max_ack_delay => 10})
    ),
    %% max_ack_delay defaults to 25 ms.
    ?assertMatch({ok, #{min_ack_delay := 25000}}, decode(#{min_ack_delay => 25000})).

min_ack_delay_above_max_ack_delay_rejected_test() ->
    ?assertEqual(
        {error, {transport_parameter_error, min_ack_delay_too_large, 10001}},
        decode(#{min_ack_delay => 10001, max_ack_delay => 10})
    ),
    ?assertEqual(
        {error, {transport_parameter_error, min_ack_delay_too_large, 25001}},
        decode(#{min_ack_delay => 25001})
    ).

min_ack_delay_not_a_varint_rejected_test() ->
    Id = quic_varint:encode(16#ff04de1b),
    ?assertMatch(
        {error, _},
        quic_tls:decode_transport_params(<<Id/binary, 3, 16#43, 16#e8, 0>>)
    ),
    ?assertMatch({error, _}, quic_tls:decode_transport_params(<<Id/binary, 0>>)).

min_ack_delay_above_max_ack_delay_closes_test() ->
    %% Section 3: TRANSPORT_PARAMETER_ERROR, whichever role sent it.
    lists:foreach(
        fun(Role) ->
            S = quic_connection:apply_peer_transport_params(
                #{min_ack_delay => 30000}, quic_connection_test_support:state_for_role(Role)
            ),
            ?assertMatch(
                {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
                S#state.close_reason
            )
        end,
        [client, server]
    ).

min_ack_delay_is_not_remembered_test() ->
    %% Section 3: never kept for a later connection.
    ?assertEqual(
        #{max_idle_timeout => 30000},
        quic_connection:remembered_transport_params(#{
            max_idle_timeout => 30000, min_ack_delay => 1000
        })
    ).

%%====================================================================
%% Where the frames may appear
%%====================================================================

not_in_long_header_or_zero_rtt_test_() ->
    [
        {lists:flatten(io_lib:format("~p in ~p", [name(Frame), Level])), fun() ->
            ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, close(Level, Frame))
        end}
     || Level <- [initial, handshake, zero_rtt],
        Frame <- [{ack_frequency, 0, 1, 1000, 1}, immediate_ack]
    ].

decode(Params) ->
    quic_tls:decode_transport_params(quic_tls:encode_transport_params(Params)).

name(Frame) when is_tuple(Frame) -> element(1, Frame);
name(Frame) -> Frame.

close(Level, Frame) ->
    (process(Level, Frame, server_state()))#state.close_reason.

process(Level, Frame, S0) ->
    quic_connection:process_frame_track_probing(Level, Frame, S0).

server_state() ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    #state{hs = HS} = S0,
    S0#state{hs = HS#hs{pn_initial = HS#hs.pn_handshake}}.

%% Without our min_ack_delay both frame types are unknown: FRAME_ENCODING_ERROR.
not_negotiated_test_() ->
    [
        {atom_to_list(name(Frame)), fun() ->
            ?assertMatch(
                {transport, ?QUIC_FRAME_ENCODING_ERROR, _}, close(app, Frame)
            )
        end}
     || Frame <- [{ack_frequency, 0, 1, 1000, 1}, immediate_ack]
    ].
