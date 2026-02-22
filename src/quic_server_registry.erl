%%% -*- erlang -*-
%%%
%%% QUIC Server Registry
%%% RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc ETS-based registry for named QUIC server lookup.
%%%
%%% This module provides a registry for named QUIC servers, allowing
%%% lookup of server information by name. The registry monitors server
%%% processes and automatically removes them when they terminate.
%%%
%%% == Usage ==
%%%
%%% ```
%%% %% Register a server
%%% ok = quic_server_registry:register(my_server, Pid, 4433, Opts).
%%%
%%% %% Look up a server
%%% {ok, #{pid := Pid, port := 4433}} = quic_server_registry:lookup(my_server).
%%%
%%% %% List all servers
%%% [my_server] = quic_server_registry:list().
%%% '''

-module(quic_server_registry).
-behaviour(gen_server).

-export([
    start_link/0,
    register/4,
    unregister/1,
    lookup/1,
    list/0,
    get_port/1,
    update_port/2,
    get_connections/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-define(TABLE, quic_server_registry_tab).

%% @private
-record(state, {
    monitors = #{} :: #{reference() => atom()}
}).

%% @private
-type state() :: #state{}.

%%====================================================================
%% API
%%====================================================================

%% @doc Start the server registry.
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, #{}, []).

%% @doc Register a named server.
-spec register(atom(), pid(), inet:port_number(), map()) -> ok.
register(Name, Pid, Port, Opts) ->
    gen_server:call(?MODULE, {register, Name, Pid, Port, Opts}, infinity).

%% @doc Unregister a named server.
-spec unregister(atom()) -> ok.
unregister(Name) ->
    gen_server:call(?MODULE, {unregister, Name}, infinity).

%% @doc Look up a server by name.
-spec lookup(atom()) -> {ok, map()} | {error, not_found}.
lookup(Name) ->
    case ets:lookup(?TABLE, Name) of
        [{Name, Info}] -> {ok, Info};
        [] -> {error, not_found}
    end.

%% @doc List all registered server names.
-spec list() -> [atom()].
list() ->
    ets:select(?TABLE, [{{'$1', '_'}, [], ['$1']}]).

%% @doc Get the port for a named server.
%% If the server was started with port 0, queries the actual bound port from a listener
%% and updates the registry for future lookups.
-spec get_port(atom()) -> {ok, inet:port_number()} | {error, not_found}.
get_port(Name) ->
    case lookup(Name) of
        {ok, #{port := 0, pid := Pid}} ->
            %% Port 0 means ephemeral - need to query actual listener
            case get_actual_port_from_listener(Pid) of
                {ok, ActualPort} ->
                    %% Update registry for future lookups
                    ok = update_port(Name, ActualPort),
                    {ok, ActualPort};
                Error ->
                    Error
            end;
        {ok, #{port := Port}} ->
            {ok, Port};
        {error, not_found} ->
            {error, not_found}
    end.

%% @doc Update the port for a named server.
%% Used when a server was started with port 0 and we've discovered the actual port.
-spec update_port(atom(), inet:port_number()) -> ok | {error, not_found}.
update_port(Name, Port) when is_atom(Name), is_integer(Port), Port > 0, Port =< 65535 ->
    case ets:lookup(?TABLE, Name) of
        [{Name, Info}] ->
            true = ets:insert(?TABLE, {Name, Info#{port => Port}}),
            ok;
        [] ->
            {error, not_found}
    end.

%% @doc Get the connection PIDs for a named server.
-spec get_connections(atom()) -> {ok, [pid()]} | {error, not_found}.
get_connections(Name) ->
    case lookup(Name) of
        {ok, #{pid := Pid}} ->
            %% Get listeners from the listener supervisor
            Listeners = quic_listener_sup:get_listeners(Pid),
            %% Collect connections from all listeners
            Connections = lists:flatmap(
                fun(ListenerPid) ->
                    try
                        quic_listener:get_connections(ListenerPid)
                    catch
                        _:_ -> []
                    end
                end,
                Listeners
            ),
            {ok, Connections};
        {error, not_found} ->
            {error, not_found}
    end.

%%====================================================================
%% gen_server callbacks
%%====================================================================

%% @private
-spec init(map()) -> {ok, state()}.
init(#{}) ->
    %% Create ETS table for server registry
    ?TABLE = ets:new(?TABLE, [
        named_table,
        set,
        public,
        {read_concurrency, true}
    ]),
    {ok, #state{}}.

%% @private
-spec handle_call(term(), gen_server:from(), state()) ->
    {reply, term(), state()}.
handle_call({register, Name, Pid, Port, Opts}, _From, #state{monitors = Monitors} = State) ->
    %% Monitor the server process
    MonRef = erlang:monitor(process, Pid),

    %% Store server info
    Info = #{
        pid => Pid,
        port => Port,
        opts => Opts,
        started_at => erlang:system_time(millisecond)
    },
    true = ets:insert(?TABLE, {Name, Info}),

    NewMonitors = Monitors#{MonRef => Name},
    {reply, ok, State#state{monitors = NewMonitors}};
handle_call({unregister, Name}, _From, #state{monitors = Monitors} = State) ->
    %% Find and remove the monitor
    case ets:lookup(?TABLE, Name) of
        [{Name, #{pid := Pid}}] ->
            %% Find the monitor reference for this pid
            MonRef = find_monitor_by_pid(Pid, Monitors),
            case MonRef of
                undefined -> ok;
                _ -> erlang:demonitor(MonRef, [flush])
            end,
            true = ets:delete(?TABLE, Name),
            NewMonitors = maps:filter(fun(_, V) -> V =/= Name end, Monitors),
            {reply, ok, State#state{monitors = NewMonitors}};
        [] ->
            {reply, ok, State}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

%% @private
-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info({'DOWN', MonRef, process, _Pid, _Reason}, #state{monitors = Monitors} = State) ->
    %% Server terminated, remove from registry
    case maps:get(MonRef, Monitors, undefined) of
        undefined ->
            {noreply, State};
        Name ->
            true = ets:delete(?TABLE, Name),
            NewMonitors = maps:remove(MonRef, Monitors),
            {noreply, State#state{monitors = NewMonitors}}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

%% @private
-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================

find_monitor_by_pid(Pid, Monitors) ->
    %% Find monitor reference by pid - need to check the registered info
    maps:fold(
        fun(MonRef, Name, Acc) ->
            case Acc of
                undefined ->
                    case ets:lookup(?TABLE, Name) of
                        [{Name, #{pid := Pid}}] -> MonRef;
                        _ -> undefined
                    end;
                _ ->
                    Acc
            end
        end,
        undefined,
        Monitors
    ).

%% @doc Get actual bound port from a listener when server was started with port 0.
%% Navigates the supervision tree: listener_sup -> listener_sup_sup -> quic_listener
get_actual_port_from_listener(ListenerSupPid) ->
    try
        %% Get children of listener_sup - includes quic_listener_sup_sup
        Children = supervisor:which_children(ListenerSupPid),
        %% Find the listener_sup_sup
        case lists:keyfind(quic_listener_sup_sup, 1, Children) of
            {quic_listener_sup_sup, SupSupPid, _, _} when is_pid(SupSupPid) ->
                %% Get listeners from sup_sup
                ListenerChildren = supervisor:which_children(SupSupPid),
                case [P || {{quic_listener, _}, P, _, _} <- ListenerChildren, is_pid(P)] of
                    [ListenerPid | _] ->
                        {ok, quic_listener:get_port(ListenerPid)};
                    [] ->
                        {error, no_listeners}
                end;
            _ ->
                {error, no_listener_sup}
        end
    catch
        _:_ ->
            {error, failed_to_get_port}
    end.
