%%% -*- erlang -*-
%%%
%%% A frame in a packet type that may not carry it is a PROTOCOL_VIOLATION
%%% (RFC 9000 Section 12.4, Table 3).

-module(quic_frame_packet_type_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

rejected_test_() ->
    [
        {lists:flatten(io_lib:format("~p in ~p", [name(Frame), Level])), fun() ->
            ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, close(Level, Frame))
        end}
     || {Level, Frame} <- [
            {initial, {max_data, 100000}},
            {handshake, {stream, 0, 0, <<"x">>, false}},
            {handshake, {new_connection_id, 1, 0, <<"cid-0001">>, <<0:128>>}},
            {handshake, {connection_close, application, 0, undefined, <<>>}},
            {zero_rtt, {ack, [{0, 0}], 0, undefined}},
            {zero_rtt, {crypto, 0, <<"x">>}},
            {zero_rtt, handshake_done},
            {zero_rtt, {new_token, <<"token">>}},
            {zero_rtt, {path_response, <<0:64>>}}
        ]
    ].

accepted_test_() ->
    [
        {lists:flatten(io_lib:format("~p in ~p", [name(Frame), Level])), fun() ->
            ?assertEqual(undefined, close(Level, Frame))
        end}
     || {Level, Frame} <- [
            {initial, ping},
            {handshake, padding},
            {zero_rtt, {max_data, 100000}},
            {zero_rtt, ping}
        ]
    ].

name(Frame) when is_tuple(Frame) -> element(1, Frame);
name(Frame) -> Frame.

close(Level, Frame) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    #state{hs = HS} = S0,
    S = quic_connection:process_frame_track_probing(Level, Frame, S0#state{
        hs = HS#hs{pn_initial = HS#hs.pn_handshake}
    }),
    S#state.close_reason.
