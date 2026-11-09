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

%% keep_alive_interval => auto is half the timeout in force.
auto_keep_alive_follows_the_peers_shorter_timeout_test() ->
    ?assertEqual(6000, auto_keep_alive(60000, #{max_idle_timeout => 12000})).

auto_keep_alive_follows_our_shorter_timeout_test() ->
    ?assertEqual(10000, auto_keep_alive(20000, #{max_idle_timeout => 60000})).

auto_keep_alive_uses_ours_when_the_peer_has_none_test() ->
    ?assertEqual(15000, auto_keep_alive(30000, #{})).

auto_keep_alive_uses_the_peers_when_ours_is_off_test() ->
    ?assertEqual(10000, auto_keep_alive(0, #{max_idle_timeout => 20000})).

auto_keep_alive_is_off_without_an_idle_timeout_test() ->
    ?assertEqual(disabled, auto_keep_alive(0, #{})).

%% Fence: an interval that was given is not touched.
explicit_keep_alive_is_kept_test() ->
    #state{cfg = Cfg} = S = state(60000, #{max_idle_timeout => 12000}, 0),
    Explicit = S#state{cfg = Cfg#conn_cfg{keep_alive_interval = 20000}},
    ?assertEqual(Explicit, quic_connection:resolve_keep_alive_interval(Explicit)).

auto_keep_alive(Local, PeerTP) ->
    ?assertEqual(
        auto, quic_connection:calculate_keep_alive_interval(#{keep_alive_interval => auto})
    ),
    #state{cfg = Cfg} = S = state(Local, PeerTP, 0),
    #state{cfg = #conn_cfg{keep_alive_interval = Interval}} =
        quic_connection:resolve_keep_alive_interval(
            S#state{cfg = Cfg#conn_cfg{keep_alive_interval = auto}}
        ),
    Interval.

%% quic:handle_timeout/2 on a connection that has idled out closes it,
%% rather than marking it closed and leaving it in its state.
handle_timeout_closes_an_idle_connection_test() ->
    ?assertMatch(
        {next_state, draining, _},
        quic_connection:handle_common_event(
            cast, handle_timeout, connected, state(30000, #{}, 40000)
        )
    ).

handle_timeout_leaves_an_active_connection_test() ->
    S = state(30000, #{}, 15000),
    ?assertEqual(
        {keep_state, S}, quic_connection:handle_common_event(cast, handle_timeout, connected, S)
    ).

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
