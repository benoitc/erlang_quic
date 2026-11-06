%%% -*- erlang -*-
%%%
%%% RESET_STREAM_AT on a connection that did not send the reset_stream_at
%%% transport parameter is a frame type unknown to it, a
%%% FRAME_ENCODING_ERROR (RFC 9000 Section 12.4).

-module(quic_reset_stream_at_unnegotiated_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).
-define(FRAME, {reset_stream_at, 3, 7, 10, 5}).

unnegotiated_is_frame_encoding_error_test() ->
    S = quic_connection:process_frame(app, ?FRAME, state(false)),
    ?assertMatch({transport, ?QUIC_FRAME_ENCODING_ERROR, _}, ?S:close_reason(S)).

negotiated_is_accepted_test() ->
    S = quic_connection:process_frame(app, ?FRAME, state(true)),
    ?assertEqual(undefined, ?S:close_reason(S)).

state(Enabled) ->
    S0 = ?S:with_keys_and_socket(?S:state_for_role(client)),
    S0#state{
        owner = self(),
        cfg = (S0#state.cfg)#conn_cfg{reset_stream_at_enabled = Enabled}
    }.
