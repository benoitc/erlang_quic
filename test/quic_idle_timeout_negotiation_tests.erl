%%% -*- erlang -*-
%%%
%%% The idle timeout is the smaller of the two advertised, and at least
%%% three PTOs (RFC 9000 Section 10.1).

-module(quic_idle_timeout_negotiation_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

closes_at_the_peers_shorter_timeout_test() ->
    ?assertMatch({next_state, draining, _}, fire(30000, #{max_idle_timeout => 10000}, 15000)).

keeps_our_timeout_when_the_peer_has_none_test() ->
    ?assertMatch({keep_state, _}, fire(30000, #{}, 15000)).

waits_three_ptos_test() ->
    ?assertMatch({keep_state, _}, fire(100, #{max_idle_timeout => 100}, 500)).

arms_the_peers_timeout_when_ours_is_off_test() ->
    S = quic_connection:set_idle_timer(state(0, #{max_idle_timeout => 10000}, 0)),
    ?assertNotEqual(undefined, S#state.idle_timer).

%% The timer is armed again once the peer's parameters are known, so a
%% connection with ours off still times out on the peer's.
arms_the_peers_timeout_once_its_parameters_arrive_test() ->
    #state{cfg = Cfg} = S0 = quic_connection_test_support:state_for_role(server),
    S1 = S0#state{
        dcid = <<"peer-cid">>,
        loss_state = quic_loss:new(),
        last_activity = erlang:monotonic_time(millisecond),
        cfg = Cfg#conn_cfg{idle_timeout = 0}
    },
    ?assertEqual(undefined, (quic_connection:set_idle_timer(S1))#state.idle_timer),
    TP = #{initial_scid => S1#state.dcid, max_idle_timeout => 10000},
    S2 = quic_connection:set_idle_timer(quic_connection:apply_peer_transport_params(TP, S1)),
    ?assertNotEqual(undefined, S2#state.idle_timer).

fire(Local, PeerTP, Idle) ->
    Ref = make_ref(),
    quic_connection:handle_common_event(
        info, {idle_timeout, Ref}, connected, (state(Local, PeerTP, Idle))#state{idle_timer = Ref}
    ).

state(Local, PeerTP, Idle) ->
    #state{cfg = Cfg} = S = quic_connection_test_support:state_for_role(client),
    S#state{
        transport_params = PeerTP,
        loss_state = quic_loss:new(),
        last_activity = erlang:monotonic_time(millisecond) - Idle,
        cfg = Cfg#conn_cfg{idle_timeout = Local}
    }.
