%%% -*- erlang -*-
%%%
%%% Frame and transport parameter values RFC 9000 rules out: a stream
%%% count above 2^60 (Section 4.6) and an empty NEW_TOKEN (Section 19.7).

-module(quic_frame_value_limits_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(TOO_MANY, (1 bsl 60) + 1).

rejected_frames_test_() ->
    [
        {Name, fun() -> ?assertMatch({transport, ?QUIC_FRAME_ENCODING_ERROR, _}, close(Frame)) end}
     || {Name, Frame} <- [
            {"MAX_STREAMS bidi", {max_streams, bidi, ?TOO_MANY}},
            {"MAX_STREAMS uni", {max_streams, uni, ?TOO_MANY}},
            {"STREAMS_BLOCKED bidi", {streams_blocked, bidi, ?TOO_MANY}},
            {"STREAMS_BLOCKED uni", {streams_blocked, uni, ?TOO_MANY}},
            {"empty NEW_TOKEN", {new_token, <<>>}}
        ]
    ].

max_streams_at_the_limit_test() ->
    ?assertEqual(undefined, close({max_streams, bidi, 1 bsl 60})).

transport_parameters_test_() ->
    [
        {atom_to_list(Key), fun() ->
            ?assertMatch(
                {error, {transport_parameter_error, _, _}},
                quic_tls:validate_transport_param_constraints(#{Key => ?TOO_MANY})
            )
        end}
     || Key <- [initial_max_streams_bidi, initial_max_streams_uni]
    ].

close(Frame) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    S = quic_connection:process_frame(app, Frame, S0#state{
        max_streams_bidi_remote = 100, max_streams_uni_remote = 100
    }),
    S#state.close_reason.
