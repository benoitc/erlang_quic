%%% -*- erlang -*-
%%%
%%% An ACK reports how long ago its largest packet number arrived (RFC
%%% 9000 Section 13.2.5), in units of 8 microseconds (the default
%%% ack_delay_exponent).

-module(quic_ack_delay_report_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

reports_the_delay_test() ->
    Now = erlang:monotonic_time(millisecond),
    ?assertMatch({ack, _, 2500, _}, quic_ack:ack_frame_for(space(5, Now - 20), Now)).

measures_from_the_largest_test() ->
    Now = erlang:monotonic_time(millisecond),
    Space = quic_ack:update_pn_space_recv(3, space(5, Now - 20), Now),
    ?assertEqual(Now - 20, Space#pn_space.recv_time).

app_ack_carries_the_delay_test() ->
    Now = erlang:monotonic_time(millisecond),
    S0 = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(client)
    ),
    S = quic_connection:send_app_ack(S0#state{pn_app = space(5, Now - 20)}),
    [Delay] = [D || {ack, _, D, _} <- S#state.pend_frames],
    ?assert(Delay >= 2500).

space(Largest, RecvTime) ->
    #pn_space{
        next_pn = 0,
        largest_recv = Largest,
        recv_time = RecvTime,
        ack_ranges = [{0, Largest}],
        ack_eliciting_in_flight = 0
    }.
