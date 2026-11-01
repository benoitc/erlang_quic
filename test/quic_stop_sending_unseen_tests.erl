%%% -*- erlang -*-
%%%
%%% STOP_SENDING for a peer stream not seen before is answered with
%%% RESET_STREAM: its sending part is in the "Ready" state (RFC 9000
%%% Section 3.5).

-module(quic_stop_sending_unseen_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%% Server: the client's first bidirectional stream.
-define(BIDI, 0).

answered_test() ->
    S = quic_connection:process_frame(app, {stop_sending, ?BIDI, 7}, server()),
    ?assertEqual([{reset_stream, ?BIDI, 7, 0}], [
        F
     || {reset_stream, _, _, _} = F <- S#state.pend_frames
    ]).

server() ->
    S = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    S#state{
        coalesce = true,
        owner = self(),
        streams = #{},
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        transport_params = #{}
    }.
