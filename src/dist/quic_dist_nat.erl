%%% -*- erlang -*-
%%%
%%% QUIC Distribution NAT Traversal
%%% NAT traversal support for QUIC distribution
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc NAT traversal support for QUIC distribution.
%%%
%%% This module provides NAT traversal capabilities including:
%%%
%%% - NAT gateway detection
%%% - External address discovery via STUN
%%% - UPnP/NAT-PMP port mapping
%%% - Connection migration on network changes
%%%
%%% NAT traversal is optional and requires the erlang_nat dependency.
%%% If erlang_nat is not available, this module gracefully degrades.
%%%
%%% == Configuration ==
%%%
%%% ```
%%% {quic, [
%%%   {dist, [
%%%     {nat_enabled, true},
%%%     {stun_servers, ["stun.l.google.com:19302"]}
%%%   ]}
%%% ]}
%%% '''
%%%
%%% @end

-module(quic_dist_nat).
-behaviour(gen_server).

-include_lib("estun/include/estun.hrl").

%% API
-export([
    start_link/0,
    start_link/1,
    is_available/0,
    discover/0,
    get_external_address/0,
    map_port/1,
    unmap_port/1,
    trigger_migration/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

%% State record
-record(state, {
    nat_available = false :: boolean(),
    external_ip :: inet:ip_address() | undefined,
    external_port :: inet:port_number() | undefined,
    mappings = #{} :: #{inet:port_number() => term()},
    stun_servers = [] :: [string()],
    renewal_timer :: reference() | undefined
}).

%% Port mapping renewal interval (25 minutes - most mappings are 30 min)
-define(RENEWAL_INTERVAL, 1500000).

%%====================================================================
%% API
%%====================================================================

%% @doc Start the NAT traversal server.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

%% @doc Start with options.
-spec start_link(Opts :: proplists:proplist()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

%% @doc Check if NAT traversal support is available.
-spec is_available() -> boolean().
is_available() ->
    case code:ensure_loaded(nat) of
        {module, nat} -> true;
        _ -> false
    end.

%% @doc Discover NAT gateway.
-spec discover() -> {ok, Gateway :: inet:ip_address()} | {error, term()}.
discover() ->
    gen_server:call(?MODULE, discover, 10000).

%% @doc Get external (public) address.
-spec get_external_address() ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
get_external_address() ->
    gen_server:call(?MODULE, get_external_address, 10000).

%% @doc Create a port mapping for the given internal port.
-spec map_port(Port :: inet:port_number()) ->
    {ok, ExternalPort :: inet:port_number()} | {error, term()}.
map_port(Port) ->
    gen_server:call(?MODULE, {map_port, Port}, 10000).

%% @doc Remove a port mapping.
-spec unmap_port(Port :: inet:port_number()) -> ok | {error, term()}.
unmap_port(Port) ->
    gen_server:call(?MODULE, {unmap_port, Port}, 10000).

%% @doc Trigger connection migration for a QUIC connection.
-spec trigger_migration(ConnRef :: reference()) -> ok | {error, term()}.
trigger_migration(ConnRef) ->
    gen_server:cast(?MODULE, {trigger_migration, ConnRef}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Opts) ->
    StunServers = proplists:get_value(stun_servers, Opts,
        ["stun.l.google.com:19302", "stun.stunprotocol.org:3478"]),

    Available = is_available(),

    State = #state{
        nat_available = Available,
        stun_servers = StunServers
    },

    %% Schedule deferred discovery to allow network to be ready
    %% This is especially important in container environments
    case Available of
        true ->
            erlang:send_after(2000, self(), do_initial_discovery);
        false ->
            ok
    end,

    {ok, State}.

handle_call(discover, _From, #state{nat_available = false} = State) ->
    {reply, {error, nat_not_available}, State};

handle_call(discover, _From, State) ->
    State1 = try_discover(State),
    case State1#state.external_ip of
        undefined ->
            {reply, {error, discovery_failed}, State1};
        IP ->
            {reply, {ok, IP}, State1}
    end;

handle_call(get_external_address, _From,
            #state{external_ip = IP, external_port = Port} = State)
  when IP =/= undefined, Port =/= undefined ->
    {reply, {ok, {IP, Port}}, State};

handle_call(get_external_address, _From, #state{nat_available = false} = State) ->
    {reply, {error, nat_not_available}, State};

handle_call(get_external_address, _From, State) ->
    %% Try STUN discovery
    State1 = try_stun_discover(State),
    case {State1#state.external_ip, State1#state.external_port} of
        {undefined, _} ->
            {reply, {error, discovery_failed}, State1};
        {IP, Port} ->
            {reply, {ok, {IP, Port}}, State1}
    end;

handle_call({map_port, Port}, _From, #state{nat_available = false} = State) ->
    %% No NAT available, return the same port
    {reply, {ok, Port}, State};

handle_call({map_port, Port}, _From, #state{mappings = Mappings} = State) ->
    case maps:get(Port, Mappings, undefined) of
        undefined ->
            %% Create new mapping
            case create_mapping(Port, State) of
                {ok, ExtPort, MappingRef} ->
                    NewMappings = maps:put(Port, {ExtPort, MappingRef}, Mappings),
                    State1 = ensure_renewal_timer(State#state{mappings = NewMappings}),
                    {reply, {ok, ExtPort}, State1};
                Error ->
                    {reply, Error, State}
            end;
        {ExtPort, _} ->
            %% Already mapped
            {reply, {ok, ExtPort}, State}
    end;

handle_call({unmap_port, Port}, _From, #state{mappings = Mappings} = State) ->
    case maps:get(Port, Mappings, undefined) of
        undefined ->
            {reply, ok, State};
        {_ExtPort, MappingRef} ->
            delete_mapping(MappingRef),
            NewMappings = maps:remove(Port, Mappings),
            {reply, ok, State#state{mappings = NewMappings}}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({trigger_migration, ConnRef}, State) ->
    %% Trigger QUIC connection migration
    catch quic:migrate(ConnRef),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(do_initial_discovery, State) ->
    %% Perform initial NAT discovery after network is ready
    State1 = try_discover(State),
    case State1#state.external_ip of
        undefined ->
            error_logger:info_msg("quic_dist_nat: Initial discovery found no NAT gateway~n");
        IP ->
            error_logger:info_msg("quic_dist_nat: Discovered external IP: ~p~n", [IP])
    end,
    {noreply, State1};

handle_info(renew_mappings, State) ->
    State1 = renew_all_mappings(State),
    State2 = schedule_renewal(State1),
    {noreply, State2};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{mappings = Mappings}) ->
    %% Clean up all mappings
    maps:foreach(
        fun(_Port, {_ExtPort, MappingRef}) ->
            catch delete_mapping(MappingRef)
        end,
        Mappings
    ),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @private
try_discover(#state{nat_available = true} = State) ->
    try
        case nat:discover() of
            ok ->
                case nat:get_external_address() of
                    {ok, IPStr} when is_list(IPStr) ->
                        case inet:parse_address(IPStr) of
                            {ok, IP} -> State#state{external_ip = IP};
                            _ -> State
                        end;
                    {ok, IP} when is_tuple(IP) ->
                        State#state{external_ip = IP};
                    _ ->
                        State
                end;
            _ ->
                State
        end
    catch
        _:_ -> State
    end;
try_discover(State) ->
    State.

%% @private
try_stun_discover(#state{stun_servers = []} = State) ->
    State;
try_stun_discover(#state{stun_servers = [Server | Rest]} = State) ->
    case stun_query(Server) of
        {ok, IP, Port} ->
            State#state{external_ip = IP, external_port = Port};
        {error, _} ->
            try_stun_discover(State#state{stun_servers = Rest})
    end.

%% @private
%% STUN binding request using estun library
stun_query(Server) ->
    case parse_stun_server(Server) of
        {ok, Host, Port} ->
            do_stun_query(Host, Port);
        Error ->
            Error
    end.

%% @private
parse_stun_server(Server) ->
    case string:tokens(Server, ":") of
        [Host, PortStr] ->
            case catch list_to_integer(PortStr) of
                Port when is_integer(Port) ->
                    {ok, Host, Port};
                _ ->
                    {error, invalid_port}
            end;
        [Host] ->
            {ok, Host, 3478};  % Default STUN port
        _ ->
            {error, invalid_server}
    end.

%% @private
do_stun_query(Host, Port) ->
    %% Use estun client for STUN binding
    case estun_client:start_link(#{}) of
        {ok, Client} ->
            try
                StunServer = #stun_server{
                    id = make_ref(),
                    host = Host,
                    port = Port,
                    transport = udp
                },
                case estun_client:bind(Client, StunServer, 5000) of
                    {ok, #stun_addr{address = IP, port = MappedPort}} ->
                        {ok, IP, MappedPort};
                    {error, Reason} ->
                        {error, Reason}
                end
            after
                estun_client:stop(Client)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @private
create_mapping(Port, #state{nat_available = true}) ->
    try
        %% Use same port for internal and external
        case nat:add_port_mapping(udp, Port, Port, 1800) of
            {ok, _, ExtPort, _, _} ->
                {ok, ExtPort, Port};
            {ok, ExtPort} ->
                {ok, ExtPort, Port};
            ok ->
                {ok, Port, Port};
            Error ->
                Error
        end
    catch
        _:Reason ->
            {error, Reason}
    end;
create_mapping(Port, _State) ->
    {ok, Port, undefined}.

%% @private
delete_mapping(Port) when is_integer(Port) ->
    try
        nat:delete_port_mapping(udp, Port, Port)
    catch
        _:_ -> ok
    end;
delete_mapping(_) ->
    ok.

%% @private
ensure_renewal_timer(#state{renewal_timer = undefined} = State) ->
    schedule_renewal(State);
ensure_renewal_timer(State) ->
    State.

%% @private
schedule_renewal(State) ->
    TRef = erlang:send_after(?RENEWAL_INTERVAL, self(), renew_mappings),
    State#state{renewal_timer = TRef}.

%% @private
renew_all_mappings(#state{mappings = Mappings, nat_available = true} = State) ->
    NewMappings = maps:fold(
        fun(Port, {ExtPort, MappingRef}, Acc) ->
            case renew_mapping(Port, ExtPort, MappingRef) of
                {ok, NewExtPort, NewRef} ->
                    maps:put(Port, {NewExtPort, NewRef}, Acc);
                {error, _} ->
                    %% Failed to renew, try to recreate
                    case create_mapping(Port, State) of
                        {ok, NewExtPort, NewRef} ->
                            maps:put(Port, {NewExtPort, NewRef}, Acc);
                        _ ->
                            Acc
                    end
            end
        end,
        #{},
        Mappings
    ),
    State#state{mappings = NewMappings};
renew_all_mappings(State) ->
    State.

%% @private
renew_mapping(_Port, ExtPort, undefined) ->
    {ok, ExtPort, undefined};
renew_mapping(Port, _ExtPort, _MappingRef) ->
    try
        case nat:add_port_mapping(udp, Port, Port, 1800) of
            {ok, _, NewExtPort, _, _} ->
                {ok, NewExtPort, Port};
            {ok, NewExtPort} ->
                {ok, NewExtPort, Port};
            ok ->
                {ok, Port, Port};
            Error ->
                Error
        end
    catch
        _:Reason ->
            {error, Reason}
    end.
