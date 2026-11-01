%%% -*- erlang -*-
%%%
%%% A RESET_STREAM for a peer stream not seen before ends its receive side
%%% like any other, so a unidirectional stream is reclaimed and its
%%% MAX_STREAMS credit returned (RFC 9000 Sections 3.2 and 4.6).

-module(quic_reset_unseen_stream_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%% Server: the client's first unidirectional stream.
-define(UNI, 2).

reclaimed_test() ->
    S = quic_connection:process_frame(app, {reset_stream, ?UNI, 0, 0}, server()),
    ?assertNot(maps:is_key(?UNI, S#state.streams)),
    ?assertEqual(101, S#state.max_streams_uni_local).

server() ->
    S = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    S#state{
        owner = self(),
        streams = #{},
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        max_data_local = 1000000,
        data_received = 0,
        cfg = (S#state.cfg)#conn_cfg{fc_max_receive_window = 1000000},
        transport_params = #{}
    }.
