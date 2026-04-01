%%% -*- erlang -*-
%%%
%%% QUIC Congestion Control Behavior and Facade
%%% RFC 9002 Section 7 - Congestion Control
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC congestion control behavior and facade module.
%%%
%%% This module defines the behavior for congestion control algorithms
%%% and provides a facade that routes to the selected algorithm module.
%%%
%%% Supported algorithms:
%%% - newreno (default): RFC 9002 NewReno implementation
%%% - bbr: BBR v1 (draft-cardwell-iccrg-bbr-congestion-control)

-module(quic_cc).

%% Behavior callbacks that algorithm modules must implement
-callback new(Opts :: map()) -> State :: term().
-callback on_packet_sent(State :: term(), Size :: non_neg_integer()) -> NewState :: term().
-callback on_packets_acked(State :: term(), AckedBytes :: non_neg_integer(), RateSample :: map()) ->
    NewState :: term().
-callback on_packets_lost(State :: term(), LostBytes :: non_neg_integer()) -> NewState :: term().
-callback on_congestion_event(State :: term(), SentTime :: non_neg_integer()) ->
    NewState :: term().
-callback on_rtt_update(
    State :: term(), SmoothedRTT :: non_neg_integer(), MinRTT :: non_neg_integer()
) -> NewState :: term().
-callback cwnd(State :: term()) -> non_neg_integer().
-callback pacing_rate(State :: term()) -> non_neg_integer().
-callback bytes_in_flight(State :: term()) -> non_neg_integer().
-callback can_send(State :: term(), Size :: non_neg_integer()) -> boolean().

%% Optional callbacks with default implementations
-optional_callbacks([]).

-export([
    %% State management
    new/0,
    new/1,

    %% Congestion control events
    on_packet_sent/2,
    on_packets_acked/2,
    on_packets_acked/3,
    on_packets_lost/2,
    on_congestion_event/2,

    %% ECN support
    on_ecn_ce/2,
    ecn_ce_counter/1,

    %% Persistent congestion
    detect_persistent_congestion/3,
    on_persistent_congestion/1,

    %% Pacing
    update_pacing_rate/2,
    pacing_allows/2,
    get_pacing_tokens/2,
    pacing_delay/2,

    %% Queries
    cwnd/1,
    ssthresh/1,
    bytes_in_flight/1,
    can_send/2,
    can_send_control/2,
    available_cwnd/1,

    %% State inspection
    in_slow_start/1,
    in_recovery/1,
    min_recovery_duration/1,
    algorithm/1
]).

%% Wrapped state: {Algorithm, AlgorithmState}
-type cc_state() :: {atom(), term()}.
-type state() :: cc_state().
-export_type([cc_state/0, state/0]).

%% CC options type for external implementations
-type cc_opts() :: #{
    algorithm => newreno | bbr,
    initial_window => pos_integer(),
    minimum_window => pos_integer(),
    min_recovery_duration => non_neg_integer(),
    max_datagram_size => pos_integer()
}.
-export_type([cc_opts/0]).

%%====================================================================
%% State Management
%%====================================================================

%% @doc Create a new congestion control state with default algorithm (NewReno).
-spec new() -> state().
new() ->
    new(#{}).

%% @doc Create a new congestion control state.
%% Options:
%%   - algorithm: newreno (default) or bbr
%%   - max_datagram_size: Maximum datagram size (default: 1200)
%%   - initial_window: Initial congestion window
%%   - minimum_window: Minimum congestion window
%%   - min_recovery_duration: Minimum time in recovery before exit (ms)
-spec new(cc_opts()) -> state().
new(Opts) ->
    Algorithm = maps:get(algorithm, Opts, newreno),
    Module = algorithm_module(Algorithm),
    AlgOpts = maps:remove(algorithm, Opts),
    State = Module:new(AlgOpts),
    {Algorithm, State}.

%%====================================================================
%% Congestion Control Events
%%====================================================================

%% @doc Record that a packet was sent.
-spec on_packet_sent(state(), non_neg_integer()) -> state().
on_packet_sent({Algorithm, State}, Size) ->
    Module = algorithm_module(Algorithm),
    {Algorithm, Module:on_packet_sent(State, Size)}.

%% @doc Process acknowledged packets.
-spec on_packets_acked(state(), non_neg_integer()) -> state().
on_packets_acked(CCState, AckedBytes) ->
    Now = erlang:monotonic_time(millisecond),
    on_packets_acked(CCState, AckedBytes, Now).

%% @doc Process acknowledged packets with largest acked sent time.
-spec on_packets_acked(state(), non_neg_integer(), non_neg_integer()) -> state().
on_packets_acked({Algorithm, State}, AckedBytes, LargestAckedSentTime) ->
    Module = algorithm_module(Algorithm),
    RateSample = #{largest_sent_time => LargestAckedSentTime},
    {Algorithm, Module:on_packets_acked(State, AckedBytes, RateSample)}.

%% @doc Process lost packets.
-spec on_packets_lost(state(), non_neg_integer()) -> state().
on_packets_lost({Algorithm, State}, LostBytes) ->
    Module = algorithm_module(Algorithm),
    {Algorithm, Module:on_packets_lost(State, LostBytes)}.

%% @doc Handle a congestion event (packet loss detected).
-spec on_congestion_event(state(), non_neg_integer()) -> state().
on_congestion_event({Algorithm, State}, SentTime) ->
    Module = algorithm_module(Algorithm),
    {Algorithm, Module:on_congestion_event(State, SentTime)}.

%%====================================================================
%% ECN Support
%%====================================================================

%% @doc Handle ECN-CE signal.
-spec on_ecn_ce(state(), non_neg_integer()) -> state().
on_ecn_ce({newreno, State}, NewCECount) ->
    {newreno, quic_cc_newreno:on_ecn_ce(State, NewCECount)};
on_ecn_ce({bbr, State}, _NewCECount) ->
    %% BBR doesn't use ECN for congestion signals in v1
    {bbr, State}.

%% @doc Get the ECN-CE counter.
-spec ecn_ce_counter(state()) -> non_neg_integer().
ecn_ce_counter({newreno, State}) ->
    quic_cc_newreno:ecn_ce_counter(State);
ecn_ce_counter({bbr, _State}) ->
    0.

%%====================================================================
%% Persistent Congestion
%%====================================================================

%% @doc Detect persistent congestion.
-spec detect_persistent_congestion(
    [{non_neg_integer(), non_neg_integer()}],
    non_neg_integer(),
    state()
) -> boolean().
detect_persistent_congestion(LostPackets, PTO, {newreno, State}) ->
    quic_cc_newreno:detect_persistent_congestion(LostPackets, PTO, State);
detect_persistent_congestion(LostPackets, PTO, {bbr, State}) ->
    quic_cc_bbr:detect_persistent_congestion(LostPackets, PTO, State).

%% @doc Reset on persistent congestion.
-spec on_persistent_congestion(state()) -> state().
on_persistent_congestion({newreno, State}) ->
    {newreno, quic_cc_newreno:on_persistent_congestion(State)};
on_persistent_congestion({bbr, State}) ->
    {bbr, quic_cc_bbr:on_persistent_congestion(State)}.

%%====================================================================
%% Pacing
%%====================================================================

%% @doc Update pacing rate based on RTT.
-spec update_pacing_rate(state(), non_neg_integer()) -> state().
update_pacing_rate({newreno, State}, SmoothedRTT) ->
    {newreno, quic_cc_newreno:update_pacing_rate(State, SmoothedRTT)};
update_pacing_rate({bbr, State}, SmoothedRTT) ->
    {bbr, quic_cc_bbr:update_pacing_rate(State, SmoothedRTT)}.

%% @doc Check if pacing allows sending.
-spec pacing_allows(state(), non_neg_integer()) -> boolean().
pacing_allows({newreno, State}, Size) ->
    quic_cc_newreno:pacing_allows(State, Size);
pacing_allows({bbr, State}, Size) ->
    quic_cc_bbr:pacing_allows(State, Size).

%% @doc Get pacing tokens.
-spec get_pacing_tokens(state(), non_neg_integer()) -> {non_neg_integer(), state()}.
get_pacing_tokens({newreno, State}, Size) ->
    {Allowed, NewState} = quic_cc_newreno:get_pacing_tokens(State, Size),
    {Allowed, {newreno, NewState}};
get_pacing_tokens({bbr, State}, Size) ->
    {Allowed, NewState} = quic_cc_bbr:get_pacing_tokens(State, Size),
    {Allowed, {bbr, NewState}}.

%% @doc Calculate pacing delay.
-spec pacing_delay(state(), non_neg_integer()) -> non_neg_integer().
pacing_delay({newreno, State}, Size) ->
    quic_cc_newreno:pacing_delay(State, Size);
pacing_delay({bbr, State}, Size) ->
    quic_cc_bbr:pacing_delay(State, Size).

%%====================================================================
%% Queries
%%====================================================================

%% @doc Get the current congestion window.
-spec cwnd(state()) -> non_neg_integer().
cwnd({Algorithm, State}) ->
    Module = algorithm_module(Algorithm),
    Module:cwnd(State).

%% @doc Get the slow start threshold.
-spec ssthresh(state()) -> non_neg_integer() | infinity.
ssthresh({newreno, State}) ->
    quic_cc_newreno:ssthresh(State);
ssthresh({bbr, _State}) ->
    %% BBR doesn't use ssthresh
    infinity.

%% @doc Get bytes currently in flight.
-spec bytes_in_flight(state()) -> non_neg_integer().
bytes_in_flight({Algorithm, State}) ->
    Module = algorithm_module(Algorithm),
    Module:bytes_in_flight(State).

%% @doc Check if we can send more bytes.
-spec can_send(state(), non_neg_integer()) -> boolean().
can_send({Algorithm, State}, Size) ->
    Module = algorithm_module(Algorithm),
    Module:can_send(State, Size).

%% @doc Check if a control message can be sent.
-spec can_send_control(state(), non_neg_integer()) -> boolean().
can_send_control({newreno, State}, Size) ->
    quic_cc_newreno:can_send_control(State, Size);
can_send_control({bbr, State}, Size) ->
    quic_cc_bbr:can_send_control(State, Size).

%% @doc Get the available congestion window.
-spec available_cwnd(state()) -> non_neg_integer().
available_cwnd({newreno, State}) ->
    quic_cc_newreno:available_cwnd(State);
available_cwnd({bbr, State}) ->
    quic_cc_bbr:available_cwnd(State).

%%====================================================================
%% State Inspection
%%====================================================================

%% @doc Check if in slow start phase.
-spec in_slow_start(state()) -> boolean().
in_slow_start({newreno, State}) ->
    quic_cc_newreno:in_slow_start(State);
in_slow_start({bbr, State}) ->
    quic_cc_bbr:in_slow_start(State).

%% @doc Check if in recovery phase.
-spec in_recovery(state()) -> boolean().
in_recovery({newreno, State}) ->
    quic_cc_newreno:in_recovery(State);
in_recovery({bbr, State}) ->
    quic_cc_bbr:in_recovery(State).

%% @doc Get minimum recovery duration.
-spec min_recovery_duration(state()) -> non_neg_integer().
min_recovery_duration({newreno, State}) ->
    quic_cc_newreno:min_recovery_duration(State);
min_recovery_duration({bbr, _State}) ->
    %% BBR doesn't use min_recovery_duration
    0.

%% @doc Get the algorithm name.
-spec algorithm(state()) -> atom().
algorithm({Algorithm, _State}) ->
    Algorithm.

%%====================================================================
%% Internal Functions
%%====================================================================

%% Map algorithm name to module
algorithm_module(newreno) -> quic_cc_newreno;
algorithm_module(bbr) -> quic_cc_bbr.
