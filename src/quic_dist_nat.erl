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

    %% Try initial discovery if NAT is available
    State1 = case Available of
        true ->
            try_discover(State);
        false ->
            State
    end,

    {ok, State1}.

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
            {ok, Context} ->
                case nat:get_external_address(Context) of
                    {ok, IP} ->
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
%% Simple STUN binding request (RFC 5389).
stun_query(Server) ->
    %% Parse server address
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
    %% Open UDP socket
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, Socket} ->
            try
                %% STUN Binding Request
                %% Type: 0x0001 (Binding Request)
                %% Length: 0 (no attributes)
                %% Magic Cookie: 0x2112A442
                %% Transaction ID: 12 random bytes
                TransactionId = crypto:strong_rand_bytes(12),
                Request = <<16#0001:16, 0:16, 16#2112A442:32, TransactionId/binary>>,

                case inet:getaddr(Host, inet) of
                    {ok, IP} ->
                        ok = gen_udp:send(Socket, IP, Port, Request),

                        case gen_udp:recv(Socket, 0, 3000) of
                            {ok, {_FromIP, _FromPort, Response}} ->
                                parse_stun_response(Response);
                            {error, timeout} ->
                                {error, timeout};
                            Error ->
                                Error
                        end;
                    Error ->
                        Error
                end
            after
                gen_udp:close(Socket)
            end;
        Error ->
            Error
    end.

%% @private
parse_stun_response(<<16#0101:16, Len:16, 16#2112A442:32, _TransId:12/binary, Attrs:Len/binary, _/binary>>) ->
    %% Binding Success Response
    parse_stun_attrs(Attrs);
parse_stun_response(_) ->
    {error, invalid_response}.

%% @private
parse_stun_attrs(<<>>) ->
    {error, no_address};
parse_stun_attrs(<<16#0020:16, Len:16, Value:Len/binary, Rest/binary>>) ->
    %% XOR-MAPPED-ADDRESS
    case Value of
        <<0, 1, XPort:16, XIP:4/binary>> ->
            %% IPv4
            Port = XPort bxor 16#2112,
            <<A, B, C, D>> = crypto:exor(XIP, <<16#2112A442:32>>),
            {ok, {A, B, C, D}, Port};
        <<0, 2, XPort:16, XIP:16/binary>> ->
            %% IPv6
            Port = XPort bxor 16#2112,
            MagicAndTxId = <<16#2112A442:32, 0:96>>,  % Simplified
            IP = crypto:exor(XIP, MagicAndTxId),
            {ok, binary_to_ip6(IP), Port};
        _ ->
            parse_stun_attrs(Rest)
    end;
parse_stun_attrs(<<16#0001:16, Len:16, Value:Len/binary, Rest/binary>>) ->
    %% MAPPED-ADDRESS (fallback)
    case Value of
        <<0, 1, Port:16, A, B, C, D>> ->
            {ok, {A, B, C, D}, Port};
        _ ->
            parse_stun_attrs(Rest)
    end;
parse_stun_attrs(<<_Type:16, Len:16, _Value:Len/binary, Rest/binary>>) ->
    %% Skip unknown attribute
    PaddedLen = (Len + 3) band (bnot 3),
    Skip = PaddedLen - Len,
    case Rest of
        <<_:Skip/binary, NextAttrs/binary>> ->
            parse_stun_attrs(NextAttrs);
        _ ->
            {error, no_address}
    end;
parse_stun_attrs(_) ->
    {error, invalid_attrs}.

%% @private
binary_to_ip6(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

%% @private
create_mapping(Port, #state{nat_available = true}) ->
    try
        case nat:discover() of
            {ok, Context} ->
                %% Request same external port as internal
                case nat:add_port_mapping(Context, udp, Port, Port, 1800) of
                    {ok, _, ExtPort, _, _} ->
                        {ok, ExtPort, {Context, Port}};
                    Error ->
                        Error
                end;
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
delete_mapping({Context, Port}) ->
    try
        nat:delete_port_mapping(Context, udp, Port)
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
renew_mapping(Port, _ExtPort, {Context, _}) ->
    try
        case nat:add_port_mapping(Context, udp, Port, Port, 1800) of
            {ok, _, NewExtPort, _, _} ->
                {ok, NewExtPort, {Context, Port}};
            Error ->
                Error
        end
    catch
        _:Reason ->
            {error, Reason}
    end;
renew_mapping(_Port, ExtPort, undefined) ->
    {ok, ExtPort, undefined}.
