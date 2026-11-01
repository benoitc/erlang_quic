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
