%%% -*- erlang -*-
%%%
%%% Property-based tests for quic_pmtu module
%%% Tests DPLPMTUD (RFC 8899) state machine properties
%%%

-module(prop_quic_pmtu).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Generators
%%====================================================================

%% Generate valid MTU values between QUIC minimum and typical max
mtu() ->
    integer(1200, 9000).

%% Generate a base MTU (typically 1200)
base_mtu() ->
    integer(1200, 1500).

%% Generate a max MTU (must be >= base)
max_mtu(BaseMTU) ->
    integer(BaseMTU, 9000).

%% Generate a PMTU state in searching mode
searching_state() ->
    ?LET(
        {BaseMTU, MaxMTU},
        ?SUCHTHAT({B, M}, {base_mtu(), mtu()}, M > B),
        begin
            SearchMin = BaseMTU,
            ProbeSize = (SearchMin + MaxMTU) div 2,
            #pmtu_state{
                state = searching,
                base_mtu = BaseMTU,
                current_mtu = BaseMTU,
                max_mtu = MaxMTU,
                probe_size = ProbeSize,
                probe_pn = 1,
                search_min = SearchMin,
                lost = [MaxMTU, undefined, undefined],
                last_probe_lost = false,
                generation = 0
            }
        end
    ).

%%====================================================================
%% Properties
%%====================================================================

%% Property: Binary search always converges
prop_binary_search_converges() ->
    ?FORALL(
        {BaseMTU, MaxMTU},
        ?SUCHTHAT({B, M}, {base_mtu(), max_mtu(1200)}, M > B + 20),
        begin
            State0 = #pmtu_state{
                state = base,
                base_mtu = BaseMTU,
                current_mtu = BaseMTU,
                max_mtu = MaxMTU,
                search_min = BaseMTU,
                lost = [MaxMTU, undefined, undefined],
                last_probe_lost = false,
                generation = 0
            },
            %% Simulate all probes succeeding
            {FinalState, Iterations} = converge_search(State0, 0, 100),
            %% Search should complete within reasonable iterations
            Iterations < 20 andalso
                quic_pmtu:get_state(FinalState) =:= search_complete
        end
    ).

%% Property: MTU never goes below base
prop_mtu_never_below_base() ->
    ?FORALL(
        {BaseMTU, MaxMTU, NumLosses},
        ?SUCHTHAT({B, M, _}, {base_mtu(), max_mtu(1200), integer(1, 20)}, M > B),
        begin
            State0 = #pmtu_state{
                state = base,
                base_mtu = BaseMTU,
                current_mtu = BaseMTU,
                max_mtu = MaxMTU,
                search_min = BaseMTU,
                lost = [MaxMTU, undefined, undefined],
                last_probe_lost = false,
                generation = 0
            },
            %% Start probing
            {Gen, State1} = quic_pmtu:on_probe_sent(1, State0),
            %% Simulate losses
            FinalState = simulate_losses(State1, NumLosses, 2, Gen),
            quic_pmtu:current_mtu(FinalState) >= BaseMTU
        end
    ).

%% Property: Probe sizes are always in valid range
prop_probe_sizes_in_range() ->
    ?FORALL(
        {BaseMTU, MaxMTU},
        ?SUCHTHAT({B, M}, {base_mtu(), max_mtu(1200)}, M > B),
        begin
            State0 = #pmtu_state{
                state = base,
                base_mtu = BaseMTU,
                current_mtu = BaseMTU,
                max_mtu = MaxMTU,
                search_min = BaseMTU,
                lost = [MaxMTU, undefined, undefined],
                last_probe_lost = false,
                generation = 0
            },
            {ProbeSize, _} = quic_pmtu:create_probe_packet(State0, 50),
            ProbeSize >= BaseMTU andalso ProbeSize =< MaxMTU
        end
    ).

%% Property: ACK always increases or maintains MTU (never decreases)
prop_ack_never_decreases_mtu() ->
    ?FORALL(
        State,
        searching_state(),
        begin
            OldMTU = quic_pmtu:current_mtu(State),
            ProbePn = State#pmtu_state.probe_pn,
            Gen = State#pmtu_state.generation,
            NewState = quic_pmtu:on_probe_acked(ProbePn, Gen, State),
            NewMTU = quic_pmtu:current_mtu(NewState),
            NewMTU >= OldMTU
        end
    ).

%% Property: Loss never increases MTU
prop_loss_never_increases_mtu() ->
    ?FORALL(
        State,
        searching_state(),
        begin
            OldMTU = quic_pmtu:current_mtu(State),
            ProbePn = State#pmtu_state.probe_pn,
            Gen = State#pmtu_state.generation,
            NewState = quic_pmtu:on_probe_lost(ProbePn, Gen, State),
            NewMTU = quic_pmtu:current_mtu(NewState),
            NewMTU =< OldMTU
        end
    ).

%% Property: Black hole detection resets to base MTU
prop_black_hole_resets_to_base() ->
    ?FORALL(
        {BaseMTU, CurrentMTU, Threshold},
        ?SUCHTHAT({B, C, _T}, {base_mtu(), mtu(), integer(3, 10)}, C > B),
        begin
            State0 = #pmtu_state{
                state = search_complete,
                base_mtu = BaseMTU,
                current_mtu = CurrentMTU,
                max_mtu = CurrentMTU + 100,
                black_hole_count = 0,
                black_hole_threshold = Threshold
            },
            %% Use a large packet size (near current MTU) for black hole detection
            LargePacketSize = CurrentMTU - 50,
            %% Simulate losses up to threshold
            FinalState = lists:foldl(
                fun(_, S) -> quic_pmtu:on_packet_lost(LargePacketSize, S) end,
                State0,
                lists:seq(1, Threshold)
            ),
            %% Should be in error state with base MTU
            quic_pmtu:get_state(FinalState) =:= error andalso
                quic_pmtu:current_mtu(FinalState) =:= BaseMTU
        end
    ).

%% Property: Small packet losses don't trigger black hole detection
prop_small_packet_losses_ignored() ->
    ?FORALL(
        {BaseMTU, CurrentMTU, NumLosses},
        ?SUCHTHAT({B, C, _N}, {base_mtu(), mtu(), integer(1, 20)}, C > B + 200),
        begin
            State0 = #pmtu_state{
                state = search_complete,
                base_mtu = BaseMTU,
                current_mtu = CurrentMTU,
                max_mtu = CurrentMTU + 100,
                black_hole_count = 0,
                black_hole_threshold = 6
            },
            %% Use a small packet size (well under threshold)
            SmallPacketSize = CurrentMTU - 200,
            %% Simulate many small packet losses
            FinalState = lists:foldl(
                fun(_, S) -> quic_pmtu:on_packet_lost(SmallPacketSize, S) end,
                State0,
                lists:seq(1, NumLosses)
            ),
            %% Should still be in search_complete with zero black hole count
            quic_pmtu:get_state(FinalState) =:= search_complete andalso
                FinalState#pmtu_state.black_hole_count =:= 0
        end
    ).

%% Property: Path change resets state properly
prop_path_change_resets_state() ->
    ?FORALL(
        {BaseMTU, CurrentMTU, MaxMTU},
        ?SUCHTHAT({B, C, M}, {base_mtu(), mtu(), mtu()}, C > B andalso M >= C),
        begin
            State0 = #pmtu_state{
                state = search_complete,
                base_mtu = BaseMTU,
                current_mtu = CurrentMTU,
                max_mtu = MaxMTU,
                search_min = CurrentMTU,
                lost = [MaxMTU, undefined, undefined],
                generation = 0
            },
            NewState = quic_pmtu:on_path_change(State0),
            %% Should reset to base MTU and be ready to probe
            quic_pmtu:current_mtu(NewState) =:= BaseMTU andalso
                quic_pmtu:get_state(NewState) =:= base andalso
                NewState#pmtu_state.search_min =:= BaseMTU andalso
                NewState#pmtu_state.lost =:= [MaxMTU, undefined, undefined]
        end
    ).

%% Property: Loss array ordering is maintained
prop_loss_array_ordering() ->
    ?FORALL(
        {Size1, Size2, Size3},
        {integer(1200, 1500), integer(1200, 1500), integer(1200, 1500)},
        begin
            %% Start with empty-ish loss array
            Lost0 = [1500, undefined, undefined],

            %% Insert losses one by one (simplified simulation)
            Lost1 = insert_test_loss(Size1, Lost0),
            Lost2 = insert_test_loss(Size2, Lost1),
            Lost3 = insert_test_loss(Size3, Lost2),

            %% Check that defined values are sorted ascending
            Defined = [V || V <- Lost3, V =/= undefined],
            Defined =:= lists:sort(Defined)
        end
    ).

%% Property: Generation counter increments on path change
prop_generation_increments() ->
    ?FORALL(
        {BaseMTU, MaxMTU, NumChanges},
        {base_mtu(), max_mtu(1200), integer(1, 10)},
        begin
            State0 = #pmtu_state{
                state = search_complete,
                base_mtu = BaseMTU,
                current_mtu = BaseMTU,
                max_mtu = MaxMTU,
                generation = 0
            },
            FinalState = lists:foldl(
                fun(_, S) -> quic_pmtu:on_path_change(S) end,
                State0,
                lists:seq(1, NumChanges)
            ),
            quic_pmtu:get_generation(FinalState) =:= NumChanges
        end
    ).

%%====================================================================
%% Helpers
%%====================================================================

%% Simulate binary search until convergence or max iterations
converge_search(State, Iterations, MaxIterations) when Iterations >= MaxIterations ->
    {State, Iterations};
converge_search(State, Iterations, MaxIterations) ->
    case quic_pmtu:get_state(State) of
        search_complete ->
            {State, Iterations};
        _ ->
            case quic_pmtu:should_probe(State) of
                true ->
                    PN = Iterations + 1,
                    {Gen, State1} = quic_pmtu:on_probe_sent(PN, State),
                    State2 = quic_pmtu:on_probe_acked(PN, Gen, State1),
                    converge_search(State2, Iterations + 1, MaxIterations);
                false ->
                    {State, Iterations}
            end
    end.

%% Simulate probe losses
simulate_losses(State, 0, _PN, _Gen) ->
    State;
simulate_losses(State, N, PN, _Gen) ->
    case quic_pmtu:should_probe(State) of
        true ->
            {NewGen, State1} = quic_pmtu:on_probe_sent(PN, State),
            State2 = quic_pmtu:on_probe_lost(PN, NewGen, State1),
            simulate_losses(State2, N - 1, PN + 1, NewGen);
        false ->
            State
    end.

%% Helper to insert loss (mimics internal insert_loss)
insert_test_loss(Size, Lost) ->
    Defined = [V || V <- Lost, V =/= undefined],
    Sorted = lists:sort([Size | Defined]),
    Trimmed = lists:sublist(Sorted, 3),
    Trimmed ++ lists:duplicate(3 - length(Trimmed), undefined).

%%====================================================================
%% EUnit test wrappers for proper tests
%%====================================================================

%% Named pmtu_prop_test_ to avoid rebar3_proper picking it up as a property
pmtu_prop_test_() ->
    {timeout, 60, [
        {"Binary search converges", fun() ->
            ?assert(proper:quickcheck(prop_binary_search_converges(), [{numtests, 100}]))
        end},
        {"MTU never below base", fun() ->
            ?assert(proper:quickcheck(prop_mtu_never_below_base(), [{numtests, 100}]))
        end},
        {"Probe sizes in range", fun() ->
            ?assert(proper:quickcheck(prop_probe_sizes_in_range(), [{numtests, 100}]))
        end},
        {"ACK never decreases MTU", fun() ->
            ?assert(proper:quickcheck(prop_ack_never_decreases_mtu(), [{numtests, 100}]))
        end},
        {"Loss never increases MTU", fun() ->
            ?assert(proper:quickcheck(prop_loss_never_increases_mtu(), [{numtests, 100}]))
        end},
        {"Black hole resets to base", fun() ->
            ?assert(proper:quickcheck(prop_black_hole_resets_to_base(), [{numtests, 100}]))
        end},
        {"Small packet losses ignored", fun() ->
            ?assert(proper:quickcheck(prop_small_packet_losses_ignored(), [{numtests, 100}]))
        end},
        {"Path change resets state", fun() ->
            ?assert(proper:quickcheck(prop_path_change_resets_state(), [{numtests, 100}]))
        end},
        {"Loss array ordering", fun() ->
            ?assert(proper:quickcheck(prop_loss_array_ordering(), [{numtests, 100}]))
        end},
        {"Generation increments", fun() ->
            ?assert(proper:quickcheck(prop_generation_increments(), [{numtests, 100}]))
        end}
    ]}.
