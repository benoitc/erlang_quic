%%% -*- erlang -*-
%%%
%%% Frames the peer may not send on a stream close the connection with
%%% STREAM_STATE_ERROR (RFC 9000 Sections 19.4, 19.5, 19.8, 19.10 and
%%% 19.13): on a stream it cannot send on, one it cannot receive on, or
%%% one of ours we have not opened.

-module(quic_stream_state_error_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%% Server: our bidi 1 and uni 3 are open; the peer may open 0 and 2.
-define(OUR_BIDI, 1).
-define(OUR_UNI, 3).
-define(UNOPENED_BIDI, 9).
-define(PEER_UNI, 2).

rejected_test_() ->
    [
        {Name, fun() -> ?assertMatch({transport, ?QUIC_STREAM_STATE_ERROR, _}, close(Frame)) end}
     || {Name, Frame} <- [
            {"RESET_STREAM on our uni", {reset_stream, ?OUR_UNI, 0, 0}},
            {"STREAM_DATA_BLOCKED on our uni", {stream_data_blocked, ?OUR_UNI, 0}},
            {"STREAM on our uni", {stream, ?OUR_UNI, 0, <<"x">>, false}},
            {"STOP_SENDING on the peer's uni", {stop_sending, ?PEER_UNI, 0}},
            {"MAX_STREAM_DATA on the peer's uni", {max_stream_data, ?PEER_UNI, 1000}},
            {"STOP_SENDING on an unopened stream", {stop_sending, ?UNOPENED_BIDI, 0}},
            {"MAX_STREAM_DATA on an unopened stream", {max_stream_data, ?UNOPENED_BIDI, 1000}}
        ]
    ].

accepted_test_() ->
    [
        {Name, fun() -> ?assertEqual(undefined, close(Frame)) end}
     || {Name, Frame} <- [
            {"STOP_SENDING on our uni", {stop_sending, ?OUR_UNI, 0}},
            {"MAX_STREAM_DATA on our bidi", {max_stream_data, ?OUR_BIDI, 2000000}},
            {"RESET_STREAM on the peer's uni", {reset_stream, ?PEER_UNI, 0, 0}}
        ]
    ].

stream_train_on_our_uni_test() ->
    Frames = fun(Off) -> [{stream, ?OUR_UNI, Off, binary:copy(<<0>>, 100), false}] end,
    S0 = quic_connection_test_support:state_with_pn_app(server(), 5),
    S = quic_connection:fold_opened([{6, 16#40, Frames(0)}, {7, 16#40, Frames(100)}], S0),
    ?assertMatch({transport, ?QUIC_STREAM_STATE_ERROR, _}, S#state.close_reason).

close(Frame) ->
    S = quic_connection:process_frame_track_probing(app, Frame, server()),
    S#state.close_reason.

server() ->
    Stream = fun(Id) ->
        #stream_state{
            id = Id,
            state = open,
            send_offset = 0,
            send_max_data = 1000000,
            send_fin = false,
            send_buffer = [],
            recv_offset = 0,
            recv_max_data = 1000000,
            recv_fin = false,
            recv_buffer = gb_trees:empty(),
            final_size = undefined
        }
    end,
    S = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    S#state{
        owner = self(),
        streams = #{?OUR_BIDI => Stream(?OUR_BIDI), ?OUR_UNI => Stream(?OUR_UNI)},
        next_stream_id_bidi = 5,
        next_stream_id_uni = 7,
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        max_data_local = 1000000,
        data_received = 0,
        cfg = (S#state.cfg)#conn_cfg{fc_max_receive_window = 1000000},
        transport_params = #{}
    }.
