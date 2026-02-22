%%% -*- erlang -*-
%%%
%%% QUIC Application Supervisor
%%% RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Top-level supervisor for the QUIC application.
%%%
%%% This module supervises:
%%% - quic_server_registry: ETS-based registry for named server lookup
%%% - quic_server_sup: Dynamic supervisor for server pools
%%%
%%% Supervision tree:
%%% ```
%%% quic_sup (one_for_one)
%%%   |-- quic_server_registry (worker)
%%%   `-- quic_server_sup (supervisor)
%%%         |-- {server_name_1, quic_listener_sup} (supervisor)
%%%         |-- {server_name_2, quic_listener_sup} (supervisor)
%%%         `-- ...
%%% '''

-module(quic_sup).
-behaviour(supervisor).

-export([
    start_link/0,
    init/1
]).

%%====================================================================
%% API
%%====================================================================

%% @doc Start the top-level QUIC supervisor.
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, #{}).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% @private
-spec init(map()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(#{}) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 5,
        period => 10
    },

    Children = [
        #{
            id => quic_server_registry,
            start => {quic_server_registry, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [quic_server_registry]
        },
        #{
            id => quic_server_sup,
            start => {quic_server_sup, start_link, []},
            restart => permanent,
            shutdown => infinity,
            type => supervisor,
            modules => [quic_server_sup]
        }
    ],

    {ok, {SupFlags, Children}}.
