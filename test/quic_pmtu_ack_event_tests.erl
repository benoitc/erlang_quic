%%% -*- erlang -*-
%%%
%%% Black hole detection, ack side, as the connection drives it: an ACK
%%% matters only while there are strikes to clear.

-module(quic_pmtu_ack_event_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

large_ack_clears_the_strikes_test() ->
    S0 = state(3),
    ?assert(quic_pmtu:has_black_hole_strikes(S0#state.pmtu_state)),
    S1 = quic_connection:handle_pmtu_ack_event([acked(1200), acked(1400)], S0),
    ?assertEqual(0, (S1#state.pmtu_state)#pmtu_state.black_hole_count),
    ?assertNot(quic_pmtu:has_black_hole_strikes(S1#state.pmtu_state)).

small_ack_leaves_the_strikes_test() ->
    S0 = state(3),
    ?assertEqual(S0, quic_connection:handle_pmtu_ack_event([acked(1200)], S0)).

ack_without_strikes_changes_nothing_test() ->
    S0 = state(0),
    ?assertEqual(S0, quic_connection:handle_pmtu_ack_event([acked(1400)], S0)).

state(Strikes) ->
    S = quic_connection_test_support:state_for_role(server),
    S#state{
        pmtu_state = #pmtu_state{
            state = search_complete,
            current_mtu = 1400,
            base_mtu = 1200,
            black_hole_count = Strikes,
            black_hole_threshold = 6
        }
    }.

acked(Size) ->
    #sent_packet{pn = 1, size = Size}.
