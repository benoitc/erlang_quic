%%% -*- erlang -*-
%%%
%%% QUIC Distribution Supervisor
%%% Supervision tree for QUIC distribution
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Supervisor for QUIC distribution components.
%%%
%%% This module supervises:
%%% - Session ticket storage (quic_dist_tickets)
%%% - NAT traversal (quic_dist_nat) when enabled
%%%
%%% @end

-module(quic_dist_sup).
-behaviour(supervisor).

%% API
-export([
    start_link/0,
    start_link/1
]).

%% Supervisor callbacks
-export([init/1]).

%%====================================================================
%% API
%%====================================================================

%% @doc Start the distribution supervisor.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

%% @doc Start the distribution supervisor with options.
-spec start_link(Opts :: proplists:proplist()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, Opts).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init(Opts) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 60
    },

    %% Session ticket storage
    TicketsSpec = #{
        id => quic_dist_tickets,
        start => {quic_dist_tickets, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker,
        modules => [quic_dist_tickets]
    },

    %% Build child specs based on configuration
    Children =
        case proplists:get_value(nat_enabled, Opts, false) of
            true ->
                NatSpec = #{
                    id => quic_dist_nat,
                    start => {quic_dist_nat, start_link, [Opts]},
                    restart => permanent,
                    shutdown => 5000,
                    type => worker,
                    modules => [quic_dist_nat]
                },
                [TicketsSpec, NatSpec];
            false ->
                [TicketsSpec]
        end,

    {ok, {SupFlags, Children}}.
