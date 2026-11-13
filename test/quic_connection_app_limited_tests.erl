%%% -*- erlang -*-
%%%
%%% A connection with nothing queued tells BBR it is application-limited
%%% (draft-ietf-ccwg-bbr-07 Section 4.1.2.4). Queued data, a deferred
%%% retransmission or another controller leaves the controller as is.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_connection_app_limited_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

empty_queue_marks_bbr_app_limited_test() ->
    #state{cc_state = CC} = S = state(bbr),
    #state{cc_state = CC1} = quic_connection:note_app_limited(S),
    ?assertEqual(quic_cc:on_app_limited(CC), CC1),
    ?assertNotEqual(CC, CC1).

queued_data_is_not_app_limited_test() ->
    S = (state(bbr))#state{send_queue_count = 1},
    ?assertEqual(S, quic_connection:note_app_limited(S)).

deferred_retransmit_is_not_app_limited_test() ->
    S = (state(bbr))#state{deferred_ctrl_retransmits = [ping]},
    ?assertEqual(S, quic_connection:note_app_limited(S)).

other_controllers_are_untouched_test() ->
    [?assertEqual(S, quic_connection:note_app_limited(S)) || S <- [state(newreno), state(cubic)]].

state(Algorithm) ->
    (quic_connection_test_support:state_for_role(client))#state{
        cc_state = quic_cc:new(Algorithm, #{})
    }.
