%%% -*- erlang -*-
%%%
%%% QUIC Path MTU Discovery (DPLPMTUD)
%%% RFC 8899 - Packetization Layer Path MTU Discovery
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC Path MTU Discovery implementation.
%%%
%%% Implements Datagram Packetization Layer Path MTU Discovery (DPLPMTUD)
%%% to dynamically discover the optimal packet size for a path.
%%%
%%% == State Machine ==
%%%
%%% The PMTU discovery follows RFC 8899 states:
%%% - `disabled': PMTU discovery not active
%%% - `base': Using base MTU (1200), ready to probe
%%% - `searching': Binary search for optimal MTU in progress
%%% - `search_complete': Found optimal MTU
%%% - `error': Black hole detected, fell back to base MTU
%%%
%%% == Binary Search Algorithm ==
%%%
%%% The module uses binary search to find the optimal MTU:
%%% 1. Start with search_low = 1200 (QUIC minimum), search_high = max_mtu
%%% 2. Probe at (search_low + search_high + 1) / 2
%%% 3. On success: search_low = probe_size, current_mtu = probe_size
%%% 4. On failure: search_high = probe_size - 1
%%% 5. Stop when search_high - search_low < SEARCH_THRESHOLD (10 bytes)
%%%

-module(quic_pmtu).

-include("quic.hrl").
-include_lib("kernel/include/logger.hrl").

-define(QUIC_LOG_META, #{domain => [erlang_quic, pmtu]}).

-export([
    %% State management
    new/0,
    new/1,

    %% Connection lifecycle
    on_connection_established/2,
    on_path_change/1,

    %% Probe lifecycle
    should_probe/1,
    create_probe_packet/2,
    on_probe_sent/2,
    on_probe_acked/2,
    on_probe_lost/2,
    on_probe_timeout/1,

    %% Black hole detection
    on_packet_lost/1,
    on_packet_acked/1,

    %% Queries
    current_mtu/1,
    is_enabled/1,
    get_state/1,

    %% Timer management
    cancel_timers/1,
    set_probe_timer/2,
    set_raise_timer/2
]).

-type pmtu_opts() :: #{
    pmtu_enabled => boolean(),
    pmtu_max_mtu => pos_integer(),
    pmtu_probe_timeout => pos_integer(),
    pmtu_raise_interval => pos_integer()
}.

-export_type([pmtu_opts/0]).

%%====================================================================
%% State Management
%%====================================================================

%% @doc Create a new PMTU state with default settings.
-spec new() -> #pmtu_state{}.
new() ->
    new(#{}).

%% @doc Create a new PMTU state with options.
%%
%% Options:
%% - `pmtu_enabled': Enable PMTU discovery (default: true)
%% - `pmtu_max_mtu': Maximum MTU to probe (default: 1500)
%%
%% @param Opts Configuration options
%% @returns New PMTU state record
-spec new(pmtu_opts()) -> #pmtu_state{}.
new(Opts) ->
    Enabled = maps:get(pmtu_enabled, Opts, true),
    MaxMTU = maps:get(pmtu_max_mtu, Opts, 1500),
    BaseMTU = 1200,

    %% When disabled, set max_mtu = base_mtu to prevent probing
    %% on_connection_established will check if there's room to probe
    EffectiveMaxMTU =
        case Enabled of
            true -> MaxMTU;
            false -> BaseMTU
        end,

    #pmtu_state{
        state = disabled,
        base_mtu = BaseMTU,
        current_mtu = BaseMTU,
        max_mtu = EffectiveMaxMTU,
        search_low = BaseMTU,
        search_high = EffectiveMaxMTU
    }.

%%====================================================================
%% Connection Lifecycle
%%====================================================================

%% @doc Initialize PMTU probing after connection is established.
%%
%% Called when the QUIC handshake completes. Uses the peer's
%% `max_udp_payload_size` transport parameter to set the upper bound.
%%
%% @param PeerMaxUdpPayloadSize Peer's advertised max UDP payload size
%% @param PMTUState Current PMTU state
%% @returns Updated PMTU state ready for probing
-spec on_connection_established(pos_integer() | undefined, #pmtu_state{}) -> #pmtu_state{}.
on_connection_established(PeerMax, #pmtu_state{max_mtu = ConfigMax, base_mtu = BaseMTU} = State) ->
    %% Determine effective max MTU
    EffectiveMax =
        case PeerMax of
            undefined -> ConfigMax;
            _ -> min(PeerMax, ConfigMax)
        end,

    %% Only enable probing if there's room to grow
    case EffectiveMax > BaseMTU of
        true ->
            ?LOG_DEBUG(
                #{
                    what => pmtu_enabled,
                    base_mtu => BaseMTU,
                    max_mtu => EffectiveMax,
                    peer_max => PeerMax,
                    config_max => ConfigMax
                },
                ?QUIC_LOG_META
            ),
            State#pmtu_state{
                state = base,
                max_mtu = EffectiveMax,
                search_high = EffectiveMax
            };
        false ->
            %% No room to probe - stay disabled
            State
    end.

%% @doc Reset PMTU state on path change (connection migration).
%%
%% RFC 8899 Section 5.3.3: PMTU should be reset on path change
%% since the new path may have different MTU characteristics.
%%
%% @param PMTUState Current PMTU state
%% @returns Reset PMTU state at base MTU
-spec on_path_change(#pmtu_state{}) -> #pmtu_state{}.
on_path_change(#pmtu_state{state = disabled} = State) ->
    State;
on_path_change(#pmtu_state{base_mtu = BaseMTU, max_mtu = MaxMTU} = State) ->
    %% Cancel any pending timers
    State1 = cancel_timers(State),
    ?LOG_DEBUG(
        #{
            what => pmtu_path_change,
            old_mtu => State#pmtu_state.current_mtu,
            new_mtu => BaseMTU
        },
        ?QUIC_LOG_META
    ),
    State1#pmtu_state{
        state = base,
        current_mtu = BaseMTU,
        probe_size = 0,
        probe_count = 0,
        probe_pn = undefined,
        search_low = BaseMTU,
        search_high = MaxMTU,
        black_hole_count = 0
    }.

%%====================================================================
%% Probe Lifecycle
%%====================================================================

%% @doc Check if we should send a probe packet.
%%
%% Returns true if:
%% - State is `base' (ready to start probing)
%% - State is `searching' and no probe is in flight
%% - State is `error' and raise timer expired
%%
%% @param PMTUState Current PMTU state
%% @returns true if a probe should be sent
-spec should_probe(#pmtu_state{}) -> boolean().
should_probe(#pmtu_state{state = disabled}) ->
    false;
should_probe(#pmtu_state{state = base}) ->
    true;
should_probe(#pmtu_state{state = searching, probe_pn = undefined}) ->
    true;
should_probe(#pmtu_state{state = error, raise_timer = undefined}) ->
    %% Ready to re-probe after error recovery
    true;
should_probe(_) ->
    false.

%% @doc Create a probe packet (PING + PADDING frames).
%%
%% Creates a packet with PING frame and PADDING to reach the target size.
%% The probe size is calculated using binary search.
%%
%% @param PMTUState Current PMTU state
%% @param HeaderSize Size of packet headers (to account for in padding)
%% @returns {ProbeSize, Frames} where Frames is [ping, {padding, N}]
-spec create_probe_packet(#pmtu_state{}, pos_integer()) ->
    {pos_integer(), [term()]}.
create_probe_packet(#pmtu_state{state = State} = PMTUState, HeaderSize) when
    State =:= base; State =:= searching; State =:= error
->
    ProbeSize = next_probe_size(PMTUState),
    %% Calculate padding needed
    %% Packet = Header + PING (1 byte) + PADDING
    PingSize = 1,
    PaddingNeeded = max(0, ProbeSize - HeaderSize - PingSize),
    Frames = [ping, {padding, PaddingNeeded}],
    {ProbeSize, Frames};
create_probe_packet(PMTUState, _HeaderSize) ->
    %% Not in a probing state - return current MTU with empty frames
    {PMTUState#pmtu_state.current_mtu, []}.

%% @doc Record that a probe packet was sent.
%%
%% @param PacketNumber Packet number of the sent probe
%% @param PMTUState Current PMTU state
%% @returns Updated PMTU state with probe in flight
-spec on_probe_sent(non_neg_integer(), #pmtu_state{}) -> #pmtu_state{}.
on_probe_sent(PacketNumber, #pmtu_state{state = State} = PMTUState) when
    State =:= base; State =:= error
->
    ProbeSize = next_probe_size(PMTUState),
    ?LOG_DEBUG(
        #{
            what => pmtu_probe_sent,
            pn => PacketNumber,
            probe_size => ProbeSize,
            state => State
        },
        ?QUIC_LOG_META
    ),
    PMTUState#pmtu_state{
        state = searching,
        probe_size = ProbeSize,
        probe_count = 1,
        probe_pn = PacketNumber
    };
on_probe_sent(PacketNumber, #pmtu_state{state = searching, probe_size = 0} = PMTUState) ->
    %% Starting a new probe after previous succeeded
    ProbeSize = next_probe_size(PMTUState),
    ?LOG_DEBUG(
        #{
            what => pmtu_probe_sent,
            pn => PacketNumber,
            probe_size => ProbeSize,
            state => searching
        },
        ?QUIC_LOG_META
    ),
    PMTUState#pmtu_state{
        probe_size = ProbeSize,
        probe_count = 1,
        probe_pn = PacketNumber
    };
on_probe_sent(PacketNumber, #pmtu_state{state = searching, probe_count = Count} = PMTUState) ->
    %% Retrying a probe that was lost or timed out
    ProbeSize = PMTUState#pmtu_state.probe_size,
    ?LOG_DEBUG(
        #{
            what => pmtu_probe_retry,
            pn => PacketNumber,
            probe_size => ProbeSize,
            attempt => Count + 1
        },
        ?QUIC_LOG_META
    ),
    PMTUState#pmtu_state{
        probe_count = Count + 1,
        probe_pn = PacketNumber
    };
on_probe_sent(_PacketNumber, PMTUState) ->
    PMTUState.

%% @doc Handle probe packet ACK.
%%
%% Called when the probe packet is acknowledged.
%% On success, updates search bounds and MTU.
%%
%% @param PacketNumber Packet number that was ACKed
%% @param PMTUState Current PMTU state
%% @returns Updated PMTU state
-spec on_probe_acked(non_neg_integer(), #pmtu_state{}) -> #pmtu_state{}.
on_probe_acked(PacketNumber, #pmtu_state{state = searching, probe_pn = PacketNumber} = PMTUState) ->
    #pmtu_state{
        probe_size = ProbeSize,
        search_high = SearchHigh
    } = PMTUState,

    %% Probe succeeded - update search_low and current_mtu
    NewSearchLow = ProbeSize,
    NewCurrentMTU = ProbeSize,

    ?LOG_DEBUG(
        #{
            what => pmtu_probe_acked,
            pn => PacketNumber,
            probe_size => ProbeSize,
            new_mtu => NewCurrentMTU
        },
        ?QUIC_LOG_META
    ),

    %% Check if search is complete
    State1 = PMTUState#pmtu_state{
        search_low = NewSearchLow,
        current_mtu = NewCurrentMTU,
        probe_size = 0,
        probe_pn = undefined,
        probe_count = 0,
        black_hole_count = 0
    },

    case SearchHigh - NewSearchLow < ?PMTU_SEARCH_THRESHOLD of
        true ->
            %% Search complete
            ?LOG_INFO(
                #{
                    what => pmtu_search_complete,
                    final_mtu => NewCurrentMTU
                },
                ?QUIC_LOG_META
            ),
            State1#pmtu_state{state = search_complete};
        false ->
            %% Continue searching
            State1#pmtu_state{state = searching}
    end;
on_probe_acked(_PacketNumber, PMTUState) ->
    %% Not our probe packet
    PMTUState.

%% @doc Handle probe packet loss.
%%
%% Called when the probe packet is detected as lost.
%% On failure, updates search bounds or retries.
%%
%% @param PacketNumber Packet number that was lost
%% @param PMTUState Current PMTU state
%% @returns Updated PMTU state
-spec on_probe_lost(non_neg_integer(), #pmtu_state{}) -> #pmtu_state{}.
on_probe_lost(PacketNumber, #pmtu_state{state = searching, probe_pn = PacketNumber} = PMTUState) ->
    #pmtu_state{
        probe_size = ProbeSize,
        probe_count = ProbeCount,
        max_probes = MaxProbes,
        search_low = SearchLow
    } = PMTUState,

    ?LOG_DEBUG(
        #{
            what => pmtu_probe_lost,
            pn => PacketNumber,
            probe_size => ProbeSize,
            attempt => ProbeCount
        },
        ?QUIC_LOG_META
    ),

    case ProbeCount >= MaxProbes of
        true ->
            %% Max retries reached - probe size doesn't work
            NewSearchHigh = ProbeSize - 1,
            State1 = PMTUState#pmtu_state{
                search_high = NewSearchHigh,
                probe_pn = undefined,
                probe_count = 0
            },

            %% Check if search is complete
            case NewSearchHigh - SearchLow < ?PMTU_SEARCH_THRESHOLD of
                true ->
                    ?LOG_INFO(
                        #{
                            what => pmtu_search_complete,
                            final_mtu => SearchLow
                        },
                        ?QUIC_LOG_META
                    ),
                    State1#pmtu_state{
                        state = search_complete,
                        current_mtu = SearchLow
                    };
                false ->
                    State1
            end;
        false ->
            %% Will retry - clear probe_pn to allow resend
            PMTUState#pmtu_state{probe_pn = undefined}
    end;
on_probe_lost(_PacketNumber, PMTUState) ->
    PMTUState.

%% @doc Handle probe timeout.
%%
%% Called when the probe timer fires.
%% Similar to loss handling but triggered by timer.
%%
%% @param PMTUState Current PMTU state
%% @returns Updated PMTU state
-spec on_probe_timeout(#pmtu_state{}) -> #pmtu_state{}.
on_probe_timeout(#pmtu_state{state = searching} = PMTUState) ->
    %% Treat timeout as loss
    #pmtu_state{
        probe_size = ProbeSize,
        probe_count = ProbeCount,
        max_probes = MaxProbes,
        search_low = SearchLow,
        probe_pn = ProbePn
    } = PMTUState,

    ?LOG_DEBUG(
        #{
            what => pmtu_probe_timeout,
            probe_size => ProbeSize,
            attempt => ProbeCount
        },
        ?QUIC_LOG_META
    ),

    State1 = PMTUState#pmtu_state{probe_timer = undefined},

    case ProbeCount >= MaxProbes of
        true ->
            %% Max retries reached
            NewSearchHigh = ProbeSize - 1,
            State2 = State1#pmtu_state{
                search_high = NewSearchHigh,
                probe_pn = undefined,
                probe_count = 0
            },
            case NewSearchHigh - SearchLow < ?PMTU_SEARCH_THRESHOLD of
                true ->
                    State2#pmtu_state{
                        state = search_complete,
                        current_mtu = SearchLow
                    };
                false ->
                    State2
            end;
        false ->
            %% Can retry - packet might still be in flight but treat as lost
            case ProbePn of
                undefined -> State1;
                _ -> State1#pmtu_state{probe_pn = undefined}
            end
    end;
on_probe_timeout(PMTUState) ->
    PMTUState#pmtu_state{probe_timer = undefined}.

%%====================================================================
%% Black Hole Detection
%%====================================================================

%% @doc Track packet loss for black hole detection.
%%
%% If we see too many consecutive losses at the current MTU,
%% fall back to base MTU.
%%
%% @param PMTUState Current PMTU state
%% @returns Updated PMTU state, possibly in error state
-spec on_packet_lost(#pmtu_state{}) -> #pmtu_state{}.
on_packet_lost(#pmtu_state{state = disabled} = State) ->
    State;
on_packet_lost(#pmtu_state{state = search_complete} = State) ->
    #pmtu_state{
        black_hole_count = Count,
        black_hole_threshold = Threshold,
        base_mtu = BaseMTU,
        max_mtu = MaxMTU
    } = State,
    NewCount = Count + 1,
    case NewCount >= Threshold of
        true ->
            %% Black hole detected - fall back to base MTU
            ?LOG_WARNING(
                #{
                    what => pmtu_black_hole_detected,
                    losses => NewCount,
                    old_mtu => State#pmtu_state.current_mtu,
                    new_mtu => BaseMTU
                },
                ?QUIC_LOG_META
            ),
            State1 = cancel_timers(State),
            State1#pmtu_state{
                state = error,
                current_mtu = BaseMTU,
                search_low = BaseMTU,
                search_high = MaxMTU,
                black_hole_count = 0,
                probe_size = 0,
                probe_count = 0,
                probe_pn = undefined
            };
        false ->
            State#pmtu_state{black_hole_count = NewCount}
    end;
on_packet_lost(State) ->
    State.

%% @doc Reset black hole counter on successful ACK.
-spec on_packet_acked(#pmtu_state{}) -> #pmtu_state{}.
on_packet_acked(#pmtu_state{black_hole_count = 0} = State) ->
    State;
on_packet_acked(State) ->
    State#pmtu_state{black_hole_count = 0}.

%%====================================================================
%% Queries
%%====================================================================

%% @doc Get the current effective MTU.
-spec current_mtu(#pmtu_state{}) -> pos_integer().
current_mtu(#pmtu_state{current_mtu = MTU}) ->
    MTU.

%% @doc Check if PMTU discovery is enabled.
-spec is_enabled(#pmtu_state{}) -> boolean().
is_enabled(#pmtu_state{state = disabled}) ->
    false;
is_enabled(_) ->
    true.

%% @doc Get the current state.
-spec get_state(#pmtu_state{}) -> disabled | base | searching | search_complete | error.
get_state(#pmtu_state{state = State}) ->
    State.

%%====================================================================
%% Timer Management
%%====================================================================

%% @doc Cancel all pending timers.
-spec cancel_timers(#pmtu_state{}) -> #pmtu_state{}.
cancel_timers(#pmtu_state{probe_timer = ProbeTimer, raise_timer = RaiseTimer} = State) ->
    cancel_timer(ProbeTimer),
    cancel_timer(RaiseTimer),
    State#pmtu_state{
        probe_timer = undefined,
        raise_timer = undefined
    }.

%% @doc Set the probe timeout timer.
-spec set_probe_timer(reference(), #pmtu_state{}) -> #pmtu_state{}.
set_probe_timer(TimerRef, State) ->
    cancel_timer(State#pmtu_state.probe_timer),
    State#pmtu_state{probe_timer = TimerRef}.

%% @doc Set the raise timer for periodic re-probing.
-spec set_raise_timer(reference(), #pmtu_state{}) -> #pmtu_state{}.
set_raise_timer(TimerRef, State) ->
    cancel_timer(State#pmtu_state.raise_timer),
    State#pmtu_state{raise_timer = TimerRef}.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @private Calculate the next probe size using binary search.
-spec next_probe_size(#pmtu_state{}) -> pos_integer().
next_probe_size(#pmtu_state{state = searching, probe_size = ProbeSize}) when ProbeSize > 0 ->
    %% In active search - use current probe size
    ProbeSize;
next_probe_size(#pmtu_state{search_low = Low, search_high = High}) ->
    %% Binary search: try the midpoint (rounded up)
    (Low + High + 1) div 2.

%% @private Cancel a timer if it's set.
-spec cancel_timer(reference() | undefined) -> ok.
cancel_timer(undefined) ->
    ok;
cancel_timer(TimerRef) ->
    erlang:cancel_timer(TimerRef),
    ok.
