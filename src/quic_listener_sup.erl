%%% -*- erlang -*-
%%%
%%% QUIC Listener Pool Supervisor
%%% RFC 9000 Section 5 - Connections
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Supervisor for a pool of QUIC listeners using SO_REUSEPORT.
%%%
%%% This module provides horizontal scaling for QUIC servers by running
%%% multiple listener processes that share the same port via reuseport.
%%% The kernel distributes incoming packets across the listeners.
%%%
%%% == Usage ==
%%%
%%% Single listener (default):
%%% ```
%%% quic_listener:start_link(Port, Opts)
%%% '''
%%%
%%% Pooled listeners for scalability:
%%% ```
%%% quic_listener_sup:start_link(Port, Opts#{pool_size => 4})
%%% '''
%%%
%%% @see quic_listener

-module(quic_listener_sup).
-behaviour(supervisor).

-export([
    start_link/2,
    stop/1,
    get_listeners/1
]).

%% supervisor callbacks
-export([init/1]).

%%====================================================================
%% API
%%====================================================================

%% @doc Start a pool of QUIC listeners on the given port.
%% Options:
%%   - pool_size: Number of listener processes (default 1)
%%   - All other options are passed to quic_listener
-spec start_link(inet:port_number(), map()) -> {ok, pid()} | {error, term()}.
start_link(Port, Opts) ->
    supervisor:start_link(?MODULE, {Port, Opts}).

%% @doc Stop the listener pool supervisor.
-spec stop(pid()) -> ok.
stop(Sup) ->
    %% First terminate all children, then stop the supervisor
    _ = [supervisor:terminate_child(Sup, Id) || {Id, _, _, _} <- supervisor:which_children(Sup)],
    exit(Sup, shutdown),
    ok.

%% @doc Get list of listener PIDs in the pool.
-spec get_listeners(pid()) -> [pid()].
get_listeners(Sup) ->
    [Pid || {_Id, Pid, _Type, _Modules} <- supervisor:which_children(Sup), is_pid(Pid)].

%%====================================================================
%% supervisor callbacks
%%====================================================================

init({Port, Opts}) ->
    PoolSize = maps:get(pool_size, Opts, 1),

    %% Create shared named ETS table for all listeners in the pool
    %% Use public access so all listener processes can read/write
    Tab = ets:new(quic_pool_connections, [set, public, {read_concurrency, true}]),

    %% Create global ticket store for 0-RTT support
    ensure_ticket_table(),

    %% Generate shared reset secret for consistent stateless resets
    ResetSecret = maps:get(reset_secret, Opts, crypto:strong_rand_bytes(32)),

    %% Configure pool options
    PoolOpts = Opts#{
        connections_table => Tab,
        reset_secret => ResetSecret,
        reuseport => PoolSize > 1
    },

    %% Create child specs for each listener in the pool
    Children = [
        #{
            id => {quic_listener, N},
            start => {quic_listener, start_link, [Port, PoolOpts]},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [quic_listener]
        }
        || N <- lists:seq(1, PoolSize)
    ],

    {ok, {#{strategy => one_for_one, intensity => 10, period => 5}, Children}}.

%%====================================================================
%% Internal Functions
%%====================================================================

%% Table name for server ticket storage (shared with quic_connection)
-define(TICKET_TABLE, quic_server_tickets).

%% Create the global ticket table if it doesn't exist
ensure_ticket_table() ->
    case ets:whereis(?TICKET_TABLE) of
        undefined ->
            try
                ets:new(?TICKET_TABLE, [named_table, public, set, {read_concurrency, true}])
            catch
                error:badarg -> ok  % Table already exists (race condition)
            end;
        _ ->
            ok
    end.
