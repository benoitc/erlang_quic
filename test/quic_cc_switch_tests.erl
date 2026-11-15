%%% -*- erlang -*-
%%%
%%% Switching congestion control algorithm on a live connection hands the
%%% packets already in flight to the new controller, so its count matches
%%% the loss tracker's and their acknowledgements bring both to zero
%%% (RFC 9002 Appendix B.4).
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cc_switch_tests).

-include_lib("eunit/include/eunit.hrl").

-define(S, quic_connection_test_support).

new_controller_carries_the_flight_test_() ->
    [{atom_to_list(A), fun() -> carries_the_flight(A) end} || A <- [newreno, cubic, bbr]].

carries_the_flight(Algorithm) ->
    S0 = lists:foldl(fun(_, Acc) -> quic_connection:send_frame(ping, Acc) end, sender(), [1, 2, 3]),
    {Bytes, Bytes} = counts(S0),
    ?assert(Bytes > 0),
    {ok, S1} = quic_connection:do_set_congestion_control(Algorithm, S0),
    ?assertEqual(Algorithm, quic_cc:algorithm(?S:state_get(S1, cc_state))),
    ?assertEqual({Bytes, Bytes}, counts(S1)),
    S2 = quic_connection:process_frame(app, {ack, [{2, 2}], 0, undefined}, S1),
    ?assertEqual({0, 0}, counts(S2)).

sender() ->
    S = ?S:state_for_admission(0, 0, 1000000, 1000000),
    ?S:state_set(S, loss_state, quic_loss:on_handshake_confirmed(quic_loss:new())).

counts(S) ->
    {
        quic_loss:bytes_in_flight(?S:loss_state(S)),
        quic_cc:bytes_in_flight(?S:state_get(S, cc_state))
    }.
