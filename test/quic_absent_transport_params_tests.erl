%%% -*- erlang -*-
%%%
%%% A flow control or stream count parameter the peer leaves out is 0
%%% (RFC 9000 Section 18.2), not our own default.

-module(quic_absent_transport_params_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(CLIENT_SCID, <<"client-scid">>).

absent_limits_are_zero_test() ->
    S = applied(#{initial_scid => ?CLIENT_SCID}),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual(
        {0, 0, 0}, {
            S#state.max_data_remote, S#state.max_streams_bidi_remote, S#state.max_streams_uni_remote
        }
    ),
    ?assertMatch(
        #{
            peer_max_stream_data_bidi_remote := 0,
            peer_max_stream_data_bidi_local := 0,
            peer_max_stream_data_uni := 0
        },
        S#state.transport_params
    ).

present_limits_are_taken_test() ->
    S = applied(#{
        initial_scid => ?CLIENT_SCID, initial_max_data => 1000, initial_max_streams_bidi => 3
    }),
    ?assertEqual({1000, 3}, {S#state.max_data_remote, S#state.max_streams_bidi_remote}).

applied(Params) ->
    S0 = quic_connection_test_support:state_set(
        quic_connection_test_support:state_for_role(server), dcid, ?CLIENT_SCID
    ),
    quic_connection:apply_peer_transport_params(Params, S0).
