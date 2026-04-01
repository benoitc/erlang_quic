%%% -*- erlang -*-
%%%
%%% Unit tests for quic_pmtu module
%%% Tests DPLPMTUD (RFC 8899) state machine
%%%

-module(quic_pmtu_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Test Generators
%%====================================================================

pmtu_test_() ->
    [
        {"State creation", fun state_creation/0},
        {"Connection established", fun connection_established/0},
        {"Connection established disabled", fun connection_established_disabled/0},
        {"Path change resets state", fun path_change_resets/0},
        {"Raise timer preserves MTU", fun raise_timer_preserves_mtu/0},
        {"Should probe logic", fun should_probe_logic/0},
        {"Probe packet creation", fun probe_packet_creation/0},
        {"Binary search convergence", fun binary_search_convergence/0},
        {"Probe ack success", fun probe_ack_success/0},
        {"Probe loss handling", fun probe_loss_handling/0},
        {"Probe timeout handling", fun probe_timeout_handling/0},
        {"Black hole detection with large packets", fun black_hole_detection/0},
        {"Black hole ignores small packet losses", fun black_hole_ignores_small_packets/0},
        {"MTU bounds validation", fun mtu_bounds_validation/0},
        {"Search threshold", fun search_threshold/0}
    ].

%%====================================================================
%% Test Cases
%%====================================================================

state_creation() ->
    %% Default state
    State1 = quic_pmtu:new(),
    ?assertEqual(disabled, quic_pmtu:get_state(State1)),
    ?assertEqual(1200, quic_pmtu:current_mtu(State1)),

    %% With options
    State2 = quic_pmtu:new(#{pmtu_max_mtu => 9000}),
    ?assertEqual(disabled, quic_pmtu:get_state(State2)),
    ?assertEqual(1200, quic_pmtu:current_mtu(State2)),

    %% Disabled explicitly
    State3 = quic_pmtu:new(#{pmtu_enabled => false}),
    ?assertEqual(disabled, quic_pmtu:get_state(State3)),
    ?assertNot(quic_pmtu:is_enabled(State3)).

connection_established() ->
    State0 = quic_pmtu:new(#{pmtu_max_mtu => 1500}),

    %% Enable after connection with peer max
    State1 = quic_pmtu:on_connection_established(1400, State0),
    ?assertEqual(base, quic_pmtu:get_state(State1)),
    ?assertEqual(1200, quic_pmtu:current_mtu(State1)),
    ?assert(quic_pmtu:is_enabled(State1)),

    %% Check max MTU is clamped to peer value
    ?assertEqual(1400, State1#pmtu_state.max_mtu),
    ?assertEqual(1400, State1#pmtu_state.search_high).

connection_established_disabled() ->
    State0 = quic_pmtu:new(#{pmtu_enabled => false}),

    %% Should stay disabled
    State1 = quic_pmtu:on_connection_established(1500, State0),
    ?assertEqual(disabled, quic_pmtu:get_state(State1)),
    ?assertNot(quic_pmtu:is_enabled(State1)).

path_change_resets() ->
    %% Start with search complete state
    State0 = #pmtu_state{
        state = search_complete,
        current_mtu = 1400,
        base_mtu = 1200,
        max_mtu = 1500,
        search_low = 1400,
        search_high = 1500
    },

    %% Path change should reset to base
    State1 = quic_pmtu:on_path_change(State0),
    ?assertEqual(base, quic_pmtu:get_state(State1)),
    ?assertEqual(1200, quic_pmtu:current_mtu(State1)),
    ?assertEqual(1200, State1#pmtu_state.search_low),
    ?assertEqual(1500, State1#pmtu_state.search_high).

raise_timer_preserves_mtu() ->
    %% Start with search complete state at 1400 MTU
    State0 = #pmtu_state{
        state = search_complete,
        current_mtu = 1400,
        base_mtu = 1200,
        max_mtu = 1500,
        search_low = 1400,
        search_high = 1500,
        raise_timer = make_ref()
    },

    %% Raise timer should preserve current MTU and start searching upward
    State1 = quic_pmtu:on_raise_timer(State0),
    ?assertEqual(searching, quic_pmtu:get_state(State1)),
    ?assertEqual(1400, quic_pmtu:current_mtu(State1)),
    ?assertEqual(1400, State1#pmtu_state.search_low),
    ?assertEqual(1500, State1#pmtu_state.search_high),
    ?assertEqual(undefined, State1#pmtu_state.raise_timer),

    %% Disabled state should remain disabled
    State2 = #pmtu_state{state = disabled},
    ?assertEqual(disabled, quic_pmtu:get_state(quic_pmtu:on_raise_timer(State2))),

    %% Already searching should just clear timer
    State3 = #pmtu_state{
        state = searching,
        current_mtu = 1300,
        raise_timer = make_ref()
    },
    State4 = quic_pmtu:on_raise_timer(State3),
    ?assertEqual(searching, quic_pmtu:get_state(State4)),
    ?assertEqual(undefined, State4#pmtu_state.raise_timer),

    %% At max MTU should not start searching
    State5 = #pmtu_state{
        state = search_complete,
        current_mtu = 1500,
        max_mtu = 1500,
        raise_timer = make_ref()
    },
    State6 = quic_pmtu:on_raise_timer(State5),
    ?assertEqual(search_complete, quic_pmtu:get_state(State6)),
    ?assertEqual(undefined, State6#pmtu_state.raise_timer).

should_probe_logic() ->
    %% Disabled state - should not probe
    State0 = quic_pmtu:new(),
    ?assertNot(quic_pmtu:should_probe(State0)),

    %% Base state - should probe
    State1 = State0#pmtu_state{state = base},
    ?assert(quic_pmtu:should_probe(State1)),

    %% Searching with no probe in flight - should probe
    State2 = State0#pmtu_state{state = searching, probe_pn = undefined},
    ?assert(quic_pmtu:should_probe(State2)),

    %% Searching with probe in flight - should not probe
    State3 = State0#pmtu_state{state = searching, probe_pn = 42},
    ?assertNot(quic_pmtu:should_probe(State3)),

    %% Search complete - should not probe
    State4 = State0#pmtu_state{state = search_complete},
    ?assertNot(quic_pmtu:should_probe(State4)),

    %% Error with raise timer - should not probe
    State5 = State0#pmtu_state{state = error, raise_timer = make_ref()},
    ?assertNot(quic_pmtu:should_probe(State5)),

    %% Error without raise timer - should probe (recovery)
    State6 = State0#pmtu_state{state = error, raise_timer = undefined},
    ?assert(quic_pmtu:should_probe(State6)).

probe_packet_creation() ->
    State0 = #pmtu_state{
        state = base,
        base_mtu = 1200,
        max_mtu = 1500,
        search_low = 1200,
        search_high = 1500
    },

    %% Create probe packet
    HeaderSize = 50,
    {ProbeSize, Frames} = quic_pmtu:create_probe_packet(State0, HeaderSize),

    %% Should be binary search midpoint: (1200 + 1500 + 1) div 2 = 1350
    ?assertEqual(1350, ProbeSize),

    %% Should have PING and PADDING frames
    ?assertEqual(2, length(Frames)),
    [Frame1, Frame2] = Frames,
    ?assertEqual(ping, Frame1),
    ?assertMatch({padding, _}, Frame2),

    %% Padding should account for header and PING
    {padding, PaddingSize} = Frame2,
    ?assertEqual(ProbeSize - HeaderSize - 1, PaddingSize).

binary_search_convergence() ->
    %% Test that binary search converges correctly
    State0 = #pmtu_state{
        state = base,
        base_mtu = 1200,
        max_mtu = 1500,
        current_mtu = 1200,
        search_low = 1200,
        search_high = 1500
    },

    %% Simulate successful probes until search complete
    %% First probe: (1200 + 1500 + 1) div 2 = 1350
    State1 = quic_pmtu:on_probe_sent(1, State0),
    ?assertEqual(searching, quic_pmtu:get_state(State1)),
    ?assertEqual(1350, State1#pmtu_state.probe_size),

    %% ACK the probe
    State2 = quic_pmtu:on_probe_acked(1, State1),
    ?assertEqual(1350, quic_pmtu:current_mtu(State2)),
    ?assertEqual(1350, State2#pmtu_state.search_low),

    %% Next probe: (1350 + 1500 + 1) div 2 = 1425
    State3 = quic_pmtu:on_probe_sent(2, State2),
    ?assertEqual(1425, State3#pmtu_state.probe_size),

    State4 = quic_pmtu:on_probe_acked(2, State3),
    ?assertEqual(1425, quic_pmtu:current_mtu(State4)),

    %% Continue until within threshold
    %% (1425 + 1500 + 1) div 2 = 1463
    State5 = quic_pmtu:on_probe_sent(3, State4),
    State6 = quic_pmtu:on_probe_acked(3, State5),
    ?assertEqual(1463, quic_pmtu:current_mtu(State6)),

    %% (1463 + 1500 + 1) div 2 = 1482
    State7 = quic_pmtu:on_probe_sent(4, State6),
    State8 = quic_pmtu:on_probe_acked(4, State7),
    ?assertEqual(1482, quic_pmtu:current_mtu(State8)),

    %% (1482 + 1500 + 1) div 2 = 1491
    State9 = quic_pmtu:on_probe_sent(5, State8),
    State10 = quic_pmtu:on_probe_acked(5, State9),
    ?assertEqual(1491, quic_pmtu:current_mtu(State10)),

    %% (1491 + 1500 + 1) div 2 = 1496
    %% After ACK: 1500 - 1496 = 4 < 10, so should be search_complete
    State11 = quic_pmtu:on_probe_sent(6, State10),
    State12 = quic_pmtu:on_probe_acked(6, State11),

    %% Search should be complete
    ?assertEqual(search_complete, quic_pmtu:get_state(State12)).

probe_ack_success() ->
    State0 = #pmtu_state{
        state = searching,
        probe_size = 1350,
        probe_pn = 42,
        current_mtu = 1200,
        search_low = 1200,
        search_high = 1500
    },

    %% ACK the correct packet
    State1 = quic_pmtu:on_probe_acked(42, State0),
    ?assertEqual(1350, quic_pmtu:current_mtu(State1)),
    ?assertEqual(1350, State1#pmtu_state.search_low),
    ?assertEqual(undefined, State1#pmtu_state.probe_pn),
    ?assertEqual(0, State1#pmtu_state.probe_count),

    %% ACK wrong packet - no change
    State2 = quic_pmtu:on_probe_acked(99, State0),
    ?assertEqual(1200, quic_pmtu:current_mtu(State2)),
    ?assertEqual(42, State2#pmtu_state.probe_pn).

probe_loss_handling() ->
    %% Test probe loss with retries
    State0 = #pmtu_state{
        state = searching,
        probe_size = 1400,
        probe_pn = 1,
        probe_count = 1,
        max_probes = 3,
        current_mtu = 1200,
        search_low = 1200,
        search_high = 1500
    },

    %% First loss - should allow retry
    State1 = quic_pmtu:on_probe_lost(1, State0),
    ?assertEqual(searching, quic_pmtu:get_state(State1)),
    ?assertEqual(undefined, State1#pmtu_state.probe_pn),
    ?assertEqual(1, State1#pmtu_state.probe_count),

    %% Retry
    State2 = quic_pmtu:on_probe_sent(2, State1),
    ?assertEqual(2, State2#pmtu_state.probe_count),

    State3 = quic_pmtu:on_probe_lost(2, State2),
    ?assertEqual(undefined, State3#pmtu_state.probe_pn),

    %% Third attempt
    State4 = quic_pmtu:on_probe_sent(3, State3),
    ?assertEqual(3, State4#pmtu_state.probe_count),

    %% Third loss - should reduce search_high
    State5 = quic_pmtu:on_probe_lost(3, State4),
    ?assertEqual(1399, State5#pmtu_state.search_high),
    ?assertEqual(0, State5#pmtu_state.probe_count).

probe_timeout_handling() ->
    State0 = #pmtu_state{
        state = searching,
        probe_size = 1400,
        probe_pn = 1,
        probe_count = 3,
        max_probes = 3,
        current_mtu = 1200,
        search_low = 1200,
        search_high = 1500,
        probe_timer = make_ref()
    },

    %% Timeout at max probes - should reduce search_high
    State1 = quic_pmtu:on_probe_timeout(State0),
    ?assertEqual(1399, State1#pmtu_state.search_high),
    ?assertEqual(undefined, State1#pmtu_state.probe_pn),
    ?assertEqual(undefined, State1#pmtu_state.probe_timer).

black_hole_detection() ->
    State0 = #pmtu_state{
        state = search_complete,
        current_mtu = 1400,
        base_mtu = 1200,
        max_mtu = 1500,
        black_hole_count = 0,
        black_hole_threshold = 6
    },

    %% Simulate consecutive losses of large packets (near current MTU)

    %% Within 100 bytes of current MTU (1400)
    LargePacketSize = 1350,
    State1 = lists:foldl(
        fun(_, S) -> quic_pmtu:on_packet_lost(LargePacketSize, S) end,
        State0,
        lists:seq(1, 5)
    ),
    ?assertEqual(search_complete, quic_pmtu:get_state(State1)),
    ?assertEqual(5, State1#pmtu_state.black_hole_count),

    %% One more loss triggers black hole detection
    State2 = quic_pmtu:on_packet_lost(LargePacketSize, State1),
    ?assertEqual(error, quic_pmtu:get_state(State2)),
    ?assertEqual(1200, quic_pmtu:current_mtu(State2)),
    ?assertEqual(0, State2#pmtu_state.black_hole_count).

black_hole_ignores_small_packets() ->
    State0 = #pmtu_state{
        state = search_complete,
        current_mtu = 1400,
        base_mtu = 1200,
        max_mtu = 1500,
        black_hole_count = 0,
        black_hole_threshold = 6
    },

    %% Small packet losses should not increment black hole counter

    %% Much smaller than current MTU - 100 = 1300
    SmallPacketSize = 200,
    State1 = lists:foldl(
        fun(_, S) -> quic_pmtu:on_packet_lost(SmallPacketSize, S) end,
        State0,
        lists:seq(1, 10)
    ),
    ?assertEqual(search_complete, quic_pmtu:get_state(State1)),
    ?assertEqual(0, State1#pmtu_state.black_hole_count),

    %% Losses of packets just under the threshold should also not count

    %% Just under 1400 - 100 = 1300
    BorderlineSize = 1299,
    State2 = lists:foldl(
        fun(_, S) -> quic_pmtu:on_packet_lost(BorderlineSize, S) end,
        State0,
        lists:seq(1, 10)
    ),
    ?assertEqual(search_complete, quic_pmtu:get_state(State2)),
    ?assertEqual(0, State2#pmtu_state.black_hole_count),

    %% Losses at the threshold should count

    %% Exactly at 1400 - 100 = 1300
    ThresholdSize = 1300,
    State3 = quic_pmtu:on_packet_lost(ThresholdSize, State0),
    ?assertEqual(1, State3#pmtu_state.black_hole_count).

mtu_bounds_validation() ->
    %% MTU should never go below base
    State0 = #pmtu_state{
        state = searching,
        probe_size = 1210,
        probe_pn = 1,
        probe_count = 3,
        max_probes = 3,
        current_mtu = 1200,
        base_mtu = 1200,
        search_low = 1200,
        search_high = 1220
    },

    %% Loss should not push MTU below base
    State1 = quic_pmtu:on_probe_lost(1, State0),
    ?assert(State1#pmtu_state.search_high >= State1#pmtu_state.base_mtu - 1),
    ?assertEqual(1200, quic_pmtu:current_mtu(State1)).

search_threshold() ->
    %% When search_high - search_low < 10, search should complete
    State0 = #pmtu_state{
        state = searching,
        probe_size = 1495,
        probe_pn = 1,
        current_mtu = 1490,
        base_mtu = 1200,
        search_low = 1490,
        search_high = 1500
    },

    %% ACK should complete search since 1500 - 1495 = 5 < 10
    State1 = quic_pmtu:on_probe_acked(1, State0),
    ?assertEqual(search_complete, quic_pmtu:get_state(State1)),
    ?assertEqual(1495, quic_pmtu:current_mtu(State1)).
