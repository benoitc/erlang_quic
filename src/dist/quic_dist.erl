%%% -*- erlang -*-
%%%
%%% QUIC Distribution Module
%%% Erlang Distribution over QUIC (RFC 9000)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Erlang distribution protocol implementation over QUIC.
%%%
%%% This module implements the Erlang distribution protocol callbacks
%%% using QUIC as the transport layer. It provides:
%%%
%%% - Connection establishment via TLS 1.3 (built into QUIC)
%%% - Multiple streams for parallel message delivery
%%% - Head-of-line blocking avoidance
%%% - Connection migration for NAT traversal
%%% - 0-RTT reconnection for fast session resumption
%%%
%%% == Configuration ==
%%%
%%% Enable QUIC distribution in vm.args:
%%% ```
%%% -proto_dist quic
%%% -epmd_module quic_epmd
%%% -start_epmd false
%%% '''
%%%
%%% Configure in sys.config:
%%% ```
%%% {quic, [
%%%   {dist, [
%%%     {cert_file, "/path/to/cert.pem"},
%%%     {key_file, "/path/to/key.pem"},
%%%     {cacert_file, "/path/to/ca.pem"},
%%%     {verify, verify_peer}
%%%   ]}
%%% ]}
%%% '''
%%%
%%% @end

-module(quic_dist).

-include("quic.hrl").
-include("quic_dist.hrl").
-include_lib("kernel/include/dist_util.hrl").
-include_lib("kernel/include/net_address.hrl").

%% Dialyzer suppressions:
%% - accept/do_accept_connection: handshake functions have complex control flow
%% - nat functions: call excluded quic_dist_nat module
-dialyzer(
    {nowarn_function, [
        accept_connection/5,
        do_accept_connection/6,
        maybe_map_nat_port/2,
        do_map_port/1
    ]}
).

%% Distribution module callbacks
-export([
    listen/1,
    listen/2,
    accept/1,
    accept_connection/5,
    setup/5,
    close/1,
    select/1,
    address/0,
    is_node_name/1
]).

%% Internal exports
-export([
    acceptor_loop/2,
    do_setup/6
]).

%%====================================================================
%% Distribution Module Callbacks
%%====================================================================

%% @doc Check if this distribution module should be used for the given node.
%% Returns true if the node name is valid and we can potentially connect.
-spec select(node()) -> boolean().
select(Node) ->
    case dist_util:split_node(Node) of
        {node, Name, Host} ->
            %% Try to resolve address via EPMD module
            EpmdMod = net_kernel:epmd_module(),
            case catch EpmdMod:address_please(Name, Host, inet) of
                {ok, _Addr} ->
                    true;
                {ok, _Addr, _Port, _Version} ->
                    true;
                _ ->
                    %% Even if address lookup fails, allow local connections
                    %% This is needed during initial node startup
                    true
            end;
        _ ->
            false
    end.

%% @doc Check if a node name is valid.
-spec is_node_name(atom()) -> boolean().
is_node_name(Node) when is_atom(Node) ->
    case split_node(atom_to_list(Node), $@, []) of
        [_, _Host] -> true;
        _ -> false
    end;
is_node_name(_) ->
    false.

%% @private
%% Split node name on separator character.
split_node([Sep | Rest], Sep, Acc) ->
    [lists:reverse(Acc) | split_node(Rest, Sep, [])];
split_node([C | Rest], Sep, Acc) ->
    split_node(Rest, Sep, [C | Acc]);
split_node([], _Sep, Acc) ->
    [lists:reverse(Acc)].

%% @doc Return the address family to use.
-spec address() -> #net_address{}.
address() ->
    {ok, Host} = inet:gethostname(),
    #net_address{
        host = Host,
        protocol = quic,
        family = inet
    }.

%% @doc Start listening for incoming distribution connections.
-spec listen(Name :: atom()) ->
    {ok, {LSocket :: term(), TcpAddress :: term(), Creation :: non_neg_integer()}}
    | {error, Reason :: term()}.
listen(Name) ->
    listen(Name, #{}).

%% @doc Start listening with options.
-spec listen(Name :: atom(), Opts :: map()) ->
    {ok, {LSocket :: term(), TcpAddress :: term(), Creation :: non_neg_integer()}}
    | {error, Reason :: term()}.
listen(Name, ExtraOpts) ->
    %% Ensure quic application is started - distribution callbacks run
    %% very early, before -eval or application start
    case ensure_quic_started() of
        ok ->
            Config = load_config(),
            Port = get_listen_port(),
            case start_quic_server(Name, Port, Config, ExtraOpts) of
                {ok, ServerName, ActualPort} ->
                    %% Request NAT port mapping if enabled
                    ExternalPort = maybe_map_nat_port(Config, ActualPort),

                    %% Create listener record
                    Listener = #quic_dist_listener{
                        server_name = ServerName,
                        port = ActualPort,
                        config = Config
                    },

                    %% Build net_address record
                    %% Use external port if NAT mapping succeeded
                    Address = #net_address{
                        address = {{0, 0, 0, 0}, ExternalPort},
                        host = localhost,
                        family = inet,
                        protocol = quic
                    },

                    %% Creation number (1-3, different for each instance)
                    Creation = get_creation(Name),

                    {ok, {Listener, Address, Creation}};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Accept a connection from the distribution listener.
-spec accept(Listen :: term()) -> AcceptPid :: pid().
accept(#quic_dist_listener{server_name = ServerName} = Listener) ->
    %% Spawn acceptor process that will handle incoming connections
    AcceptorPid = spawn_link(?MODULE, acceptor_loop, [self(), Listener]),
    %% Register acceptor so handle_new_connection can notify it
    persistent_term:put({quic_dist_acceptor, ServerName}, AcceptorPid),
    AcceptorPid.

%% @doc Handle an accepted connection.
%% Called by net_kernel when a new connection is accepted.
-spec accept_connection(
    AcceptPid :: pid(),
    Socket :: term(),
    MyNode :: node(),
    Allowed :: term(),
    SetupTime :: non_neg_integer()
) -> pid().
accept_connection(AcceptPid, DistCtrl, MyNode, Allowed, SetupTime) ->
    %% IMPORTANT: self() here is net_kernel - capture it before spawning
    Kernel = self(),
    spawn_opt(
        fun() ->
            %% Register with acceptor so we receive the controller message
            AcceptPid ! {register_pending, DistCtrl, self()},
            do_accept_connection(AcceptPid, DistCtrl, MyNode, Allowed, SetupTime, Kernel)
        end,
        [link, {priority, max}]
    ).

%% @doc Set up an outgoing distribution connection.
%% Called by net_kernel to establish a connection to another node.
-spec setup(
    Node :: node(),
    Type :: atom(),
    MyNode :: node(),
    LongOrShortNames :: shortnames | longnames,
    SetupTime :: non_neg_integer()
) -> pid().
setup(Node, Type, MyNode, LongOrShortNames, SetupTime) ->
    spawn_opt(
        ?MODULE,
        do_setup,
        [self(), Node, Type, MyNode, LongOrShortNames, SetupTime],
        [link, {priority, max}]
    ).

%% @doc Close the distribution listener.
-spec close(Listen :: term()) -> ok.
close(#quic_dist_listener{server_name = ServerName}) ->
    %% First try to stop via supervised server
    catch quic:stop_server(ServerName),
    %% Also check for early boot standalone listener
    Key = {quic_dist_early_listener, ServerName},
    case persistent_term:get(Key, undefined) of
        undefined ->
            ok;
        #{pid := Pid} ->
            catch quic_listener:stop(Pid),
            catch persistent_term:erase(Key),
            ok
    end;
close(_) ->
    ok.

%%====================================================================
%% Internal Functions - Server Setup
%%====================================================================

%% @private
%% Ensure minimal QUIC resources are available for distribution.
%%
%% This function handles the tricky boot sequence:
%% - When using -proto_dist quic, listen/1 is called BEFORE applications start
%% - Calling application:ensure_all_started(quic) would deadlock
%% - Instead, we initialize only the minimal required resources:
%%   1. Ensure crypto is loaded (for TLS operations)
%%   2. Create discovery ETS table (for node lookup)
%%   3. Set early boot flag so start_quic_server uses standalone listener
%%
%% Once boot completes and the quic application starts normally, it will
%% detect and adopt these early boot resources.
ensure_quic_started() ->
    case whereis(quic_sup) of
        Pid when is_pid(Pid) ->
            %% quic application is already running, nothing to do
            ok;
        undefined ->
            %% Early boot - initialize minimal resources without starting app
            ensure_quic_minimal()
    end.

%% @private
%% Minimal initialization for early boot (before quic application starts).
ensure_quic_minimal() ->
    %% Ensure crypto is available - needed for TLS
    case code:ensure_loaded(crypto) of
        {module, crypto} ->
            %% Create discovery ETS table if it doesn't exist
            ensure_discovery_table(),
            %% Mark that we're in early boot mode
            put(quic_dist_early_boot, true),
            ok;
        {error, Reason} ->
            {error, {crypto_not_available, Reason}}
    end.

%% @private
%% Create the discovery ETS table used by quic_discovery_static.
%% This is normally created by quic_sup:init/1.
ensure_discovery_table() ->
    case ets:info(quic_discovery_static_nodes) of
        undefined ->
            ets:new(
                quic_discovery_static_nodes,
                [named_table, public, set, {read_concurrency, true}]
            );
        _ ->
            ok
    end.

%% @private
%% Load distribution configuration from command-line args and application environment.
%% Command-line arguments take precedence (using -quic_dist key value format).
load_config() ->
    %% First check init arguments (command line), then fall back to app env
    DistOpts = application:get_env(quic, dist, []),

    #quic_dist_config{
        cert_file = get_init_arg(cert, get_opt(cert_file, DistOpts)),
        key_file = get_init_arg(key, get_opt(key_file, DistOpts)),
        cacert_file = get_init_arg(cacert, get_opt(cacert_file, DistOpts)),
        cert = get_opt(cert, DistOpts),
        key = get_opt(key, DistOpts),
        cacert = get_opt(cacert, DistOpts),
        verify = get_verify_opt(get_opt(verify, DistOpts, verify_none)),
        discovery_module = get_opt(discovery_module, DistOpts, quic_discovery_static),
        nodes = get_opt(nodes, DistOpts, []),
        dns_domain = get_opt(dns_domain, DistOpts),
        nat_enabled = get_opt(nat_enabled, DistOpts, false),
        stun_servers = get_opt(stun_servers, DistOpts, []),
        lb_enabled = get_opt(lb_enabled, DistOpts, false),
        lb_server_id = get_opt(lb_server_id, DistOpts, auto),
        lb_key = get_opt(lb_key, DistOpts),
        %% Backpressure tuning
        congestion_threshold = get_opt(
            congestion_threshold, DistOpts, ?DEFAULT_QUEUE_CONGESTION_THRESHOLD
        ),
        max_pull_per_notification = get_opt(
            max_pull_per_notification, DistOpts, ?DEFAULT_MAX_PULL_PER_NOTIFICATION
        ),
        backpressure_retry_ms = get_opt(
            backpressure_retry_ms, DistOpts, ?DEFAULT_BACKPRESSURE_RETRY_MS
        )
    }.

%% @private
%% Get value from init argument -quic_dist_Key Value
get_init_arg(Key, Default) ->
    ArgName = list_to_atom("quic_dist_" ++ atom_to_list(Key)),
    case init:get_argument(ArgName) of
        {ok, [[Value]]} ->
            Value;
        _ ->
            %% Also try plain -quic_dist with key value pairs
            case init:get_argument(quic_dist) of
                {ok, Args} ->
                    find_in_args(atom_to_list(Key), Args, Default);
                _ ->
                    Default
            end
    end.

%% @private
find_in_args(_Key, [], Default) -> Default;
find_in_args(Key, [[Key, Value] | _], _Default) -> Value;
find_in_args(Key, [_ | Rest], Default) -> find_in_args(Key, Rest, Default).

%% @private
get_verify_opt(verify_peer) -> verify_peer;
get_verify_opt(verify_none) -> verify_none;
get_verify_opt("verify_peer") -> verify_peer;
get_verify_opt("verify_none") -> verify_none;
get_verify_opt(_) -> verify_none.

%% @private
get_opt(Key, Opts) ->
    get_opt(Key, Opts, undefined).

get_opt(Key, Opts, Default) when is_list(Opts) ->
    proplists:get_value(Key, Opts, Default);
get_opt(Key, Opts, Default) when is_map(Opts) ->
    maps:get(Key, Opts, Default).

%% @private
%% Get the port to listen on from init arguments or config.
get_listen_port() ->
    case init:get_argument(quic_dist_port) of
        {ok, [[PortStr]]} ->
            list_to_integer(PortStr);
        _ ->
            application:get_env(quic, dist_port, ?QUIC_DIST_DEFAULT_PORT)
    end.

%% @private
%% Start QUIC server for distribution.
%%
%% Two modes of operation:
%% 1. Early boot mode: Start standalone quic_listener directly (no supervision)
%% 2. Normal mode: Use quic:start_server through the supervisor tree
start_quic_server(Name, Port, Config, _ExtraOpts) ->
    %% Load certificate and key
    case load_credentials(Config) of
        {ok, Cert, Key, _CACert} ->
            CongestionThreshold = Config#quic_dist_config.congestion_threshold,
            Opts = #{
                cert => Cert,
                key => Key,
                alpn => [?QUIC_DIST_ALPN],
                idle_timeout => ?QUIC_DIST_IDLE_TIMEOUT,
                %% Use higher initial cwnd for distribution bulk transfers
                initial_window => ?INITIAL_WINDOW_DISTRIBUTION,
                %% Keep a higher congestion floor to avoid liveness stalls
                %% on bursty virtual networks (e.g., Docker bridge).
                minimum_window => ?MINIMUM_WINDOW_DISTRIBUTION,
                %% Higher flow control limits for distribution to avoid blocking
                %% during large message transfers (code loading, large terms)
                max_data => ?DIST_INITIAL_MAX_DATA,
                max_stream_data_bidi_local => ?DIST_INITIAL_MAX_STREAM_DATA,
                max_stream_data_bidi_remote => ?DIST_INITIAL_MAX_STREAM_DATA,
                max_stream_data_uni => ?DIST_INITIAL_MAX_STREAM_DATA,
                %% Backpressure threshold for congestion detection
                congestion_threshold => CongestionThreshold,
                connection_handler => fun(ConnPid, ConnRef) ->
                    handle_new_connection(ConnPid, ConnRef)
                end
            },

            case whereis(quic_sup) of
                Pid when is_pid(Pid) ->
                    %% Normal mode - use supervised server
                    start_supervised_server(Name, Port, Opts);
                undefined ->
                    %% Early boot mode - start standalone listener
                    start_standalone_listener(Name, Port, Opts)
            end;
        {error, Reason} ->
            {error, {credentials, Reason}}
    end.

%% @private
%% Start QUIC server through the normal supervisor tree.
start_supervised_server(Name, Port, Opts) ->
    ServerName = dist_server_name(Name),
    case quic:start_server(ServerName, Port, Opts) of
        {ok, _Pid} ->
            %% Get actual port (may differ if Port was 0)
            case quic:get_server_port(ServerName) of
                {ok, ActualPort} ->
                    {ok, ServerName, ActualPort};
                Error ->
                    quic:stop_server(ServerName),
                    Error
            end;
        Error ->
            Error
    end.

%% @private
%% Start a standalone QUIC listener during early boot.
%% This bypasses the supervisor tree since quic_sup isn't running yet.
%% The listener is NOT linked to the distribution process to avoid
%% crashing if distribution restarts.
start_standalone_listener(Name, Port, Opts) ->
    ServerName = dist_server_name(Name),
    case quic_listener:start(Port, Opts) of
        {ok, ListenerPid} ->
            %% Get actual port
            ActualPort = quic_listener:get_port(ListenerPid),
            %% Register the listener for later adoption by quic_sup
            register_early_boot_listener(ServerName, ListenerPid, ActualPort),
            {ok, ServerName, ActualPort};
        {error, Reason} ->
            {error, Reason}
    end.

%% @private
%% Register an early boot listener so it can be found and adopted
%% when the quic application starts.
register_early_boot_listener(Name, Pid, Port) ->
    %% Store in persistent_term for cross-process access
    Key = {quic_dist_early_listener, Name},
    persistent_term:put(Key, #{pid => Pid, port => Port, name => Name}),
    ok.

%% @private
dist_server_name(Name) ->
    list_to_atom("quic_dist_" ++ atom_to_list(Name)).

%% @private
%% Get creation number (1-3) for the node.
%% Different instances should have different creation numbers.
get_creation(Name) ->
    (erlang:phash2(Name) + erlang:system_time(second)) rem 3 + 1.

%% @private
%% Request NAT port mapping if NAT is enabled.
%% Returns the external port (may differ from internal port).
%%
%% Note: During early boot (before quic application starts), the NAT
%% gen_server may not be running. In this case, we schedule deferred
%% port mapping to be performed once the application is fully started.
maybe_map_nat_port(#quic_dist_config{nat_enabled = true}, Port) ->
    %% NAT is enabled - try to create port mapping
    case quic_dist_nat:is_available() of
        true ->
            %% Check if NAT server is running
            case whereis(quic_dist_nat) of
                Pid when is_pid(Pid) ->
                    %% Server is running, try immediate mapping
                    do_map_port(Port);
                undefined ->
                    %% Server not running yet (early boot), schedule deferred mapping
                    schedule_deferred_nat_mapping(Port),
                    Port
            end;
        false ->
            error_logger:info_msg("quic_dist: NAT enabled but nat library not available~n"),
            Port
    end;
maybe_map_nat_port(_, Port) ->
    %% NAT not enabled
    Port.

%% @private
%% Actually perform the port mapping.
do_map_port(Port) ->
    case quic_dist_nat:map_port(Port) of
        {ok, ExternalPort} ->
            error_logger:info_msg(
                "quic_dist: NAT port mapping created ~p -> ~p~n",
                [Port, ExternalPort]
            ),
            ExternalPort;
        {error, Reason} ->
            error_logger:warning_msg("quic_dist: NAT port mapping failed: ~p~n", [Reason]),
            Port
    end.

%% @private
%% Schedule deferred NAT port mapping for after application start.
%% The mapping will be attempted once quic_dist_nat gen_server is available.
schedule_deferred_nat_mapping(Port) ->
    error_logger:info_msg("quic_dist: Scheduling deferred NAT port mapping for port ~p~n", [Port]),
    %% Store the port for deferred mapping
    persistent_term:put(quic_dist_deferred_nat_port, Port),
    %% Spawn a process to attempt mapping once the server is available
    spawn(fun() -> deferred_nat_mapping_loop(Port, 30) end),
    ok.

%% @private
%% Loop waiting for NAT server to be available and ready, then create mapping.
%% We wait extra time after server starts to allow NAT gateway discovery.
deferred_nat_mapping_loop(_Port, 0) ->
    error_logger:warning_msg("quic_dist: Deferred NAT port mapping timed out~n"),
    ok;
deferred_nat_mapping_loop(Port, Retries) ->
    timer:sleep(1000),
    case whereis(quic_dist_nat) of
        Pid when is_pid(Pid) ->
            %% Server is running, wait a bit for discovery to complete
            %% The NAT server schedules discovery 2s after start
            timer:sleep(3000),
            _ExtPort = do_map_port(Port),
            persistent_term:erase(quic_dist_deferred_nat_port),
            ok;
        undefined ->
            deferred_nat_mapping_loop(Port, Retries - 1)
    end.

%% @private
%% Load TLS credentials from files or config.
load_credentials(#quic_dist_config{cert = Cert, key = Key, cacert = CACert}) when
    Cert =/= undefined, Key =/= undefined
->
    {ok, Cert, Key, CACert};
load_credentials(#quic_dist_config{
    cert_file = CertFile,
    key_file = KeyFile,
    cacert_file = CACertFile
}) when CertFile =/= undefined, KeyFile =/= undefined ->
    try
        {ok, CertPem} = file:read_file(CertFile),
        {ok, KeyPem} = file:read_file(KeyFile),

        %% Decode PEM to DER
        [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),

        %% Decode private key - must be fully decoded record for crypto:sign
        KeyDer =
            case public_key:pem_decode(KeyPem) of
                [{'RSAPrivateKey', Der, not_encrypted}] ->
                    public_key:der_decode('RSAPrivateKey', Der);
                [{'ECPrivateKey', Der, not_encrypted}] ->
                    public_key:der_decode('ECPrivateKey', Der);
                [{'PrivateKeyInfo', Der, not_encrypted}] ->
                    %% PKCS#8 format - decode and extract the key
                    public_key:der_decode('PrivateKeyInfo', Der);
                [{Type, Der, not_encrypted}] ->
                    %% Fallback - try to decode as the specified type
                    public_key:der_decode(Type, Der);
                [Entry] ->
                    Entry
            end,

        %% Load CA certificate if provided
        CACertDer =
            case CACertFile of
                undefined ->
                    undefined;
                _ ->
                    {ok, CACertPem} = file:read_file(CACertFile),
                    [{'Certificate', CADer, _}] = public_key:pem_decode(CACertPem),
                    CADer
            end,

        {ok, CertDer, KeyDer, CACertDer}
    catch
        _:Reason ->
            {error, {load_credentials, Reason}}
    end;
load_credentials(_) ->
    {error, no_credentials}.

%% @private
%% Handle a new incoming QUIC connection.
handle_new_connection(ConnPid, ConnRef) ->
    error_logger:info_msg(
        "quic_dist: handle_new_connection called, ConnPid=~p, ConnRef=~p~n",
        [ConnPid, ConnRef]
    ),
    %% Start distribution controller for this connection
    case quic_dist_controller:start_link(ConnPid, ConnRef, server) of
        {ok, ControllerPid} ->
            error_logger:info_msg("quic_dist: server controller started: ~p~n", [ControllerPid]),
            %% Notify the acceptor about the new connection
            %% The server name is based on the short node name (before @)
            NodeName = node(),
            ShortName =
                case NodeName of
                    nonode@nohost ->
                        nonode;
                    _ ->
                        NodeStr = atom_to_list(NodeName),
                        case string:split(NodeStr, "@") of
                            [Name, _Host] -> list_to_atom(Name);
                            [Name] -> list_to_atom(Name)
                        end
                end,
            ServerName = dist_server_name(ShortName),
            case persistent_term:get({quic_dist_acceptor, ServerName}, undefined) of
                undefined ->
                    %% No acceptor registered yet, this is normal during early boot
                    %% The kernel will eventually call accept/1
                    ok;
                AcceptorPid when is_pid(AcceptorPid) ->
                    %% Notify acceptor - NodeName will be extracted during handshake
                    AcceptorPid ! {accept, ControllerPid, undefined}
            end,
            {ok, ControllerPid};
        Error ->
            error_logger:error_msg("quic_dist: Failed to start controller: ~p~n", [Error]),
            Error
    end.

%%====================================================================
%% Internal Functions - Acceptor
%%====================================================================

%% @private
%% Acceptor loop - waits for distribution controller to report connections.
acceptor_loop(Kernel, #quic_dist_listener{} = Listener) ->
    acceptor_loop(Kernel, Listener, #{}).

acceptor_loop(Kernel, #quic_dist_listener{} = Listener, Pending) ->
    %% Pending maps SpawnedPid -> {waiting, DistCtrl} | {ready, DistCtrl}
    %% - {waiting, DistCtrl} = do_accept_connection (SpawnedPid) waiting for controller message
    %% - {ready, DistCtrl} = controller message received, waiting for registration
    %% Note: Kernel uses SpawnedPid (return value of accept_connection) in controller message
    receive
        {accept, DistCtrl, _NodeName} ->
            %% Report accepted connection to kernel
            Kernel ! {accept, self(), DistCtrl, inet, quic},
            %% Continue accepting
            acceptor_loop(Kernel, Listener, Pending);
        {Kernel, controller, SpawnedPid} ->
            %% Kernel notifying us about the controller process - SpawnedPid is the do_accept_connection process
            %% Lookup by SpawnedPid to find the waiting entry
            %% Note: We only respond to SpawnedPid, NOT to Kernel (kernel doesn't expect a response)
            case maps:get(SpawnedPid, Pending, undefined) of
                undefined ->
                    %% No registration yet - buffer with ready state
                    acceptor_loop(
                        Kernel, Listener, maps:put(SpawnedPid, {ready, undefined}, Pending)
                    );
                {waiting, DistCtrl} ->
                    %% Someone waiting - set supervisor and respond only to SpawnedPid
                    ok = quic_dist_controller:set_supervisor(DistCtrl, Kernel),
                    SpawnedPid ! {self(), controller},
                    acceptor_loop(Kernel, Listener, maps:remove(SpawnedPid, Pending));
                {ready, _} ->
                    %% Already ready (shouldn't happen), just continue
                    acceptor_loop(Kernel, Listener, Pending)
            end;
        {register_pending, DistCtrl, SpawnedPid} ->
            %% Register a pending do_accept_connection process
            %% SpawnedPid is self() of do_accept_connection, DistCtrl is the controller
            case maps:get(SpawnedPid, Pending, undefined) of
                undefined ->
                    %% Not ready yet - register as waiting
                    acceptor_loop(
                        Kernel, Listener, maps:put(SpawnedPid, {waiting, DistCtrl}, Pending)
                    );
                {ready, _} ->
                    %% Kernel already sent controller message - set supervisor and respond only to SpawnedPid
                    ok = quic_dist_controller:set_supervisor(DistCtrl, Kernel),
                    SpawnedPid ! {self(), controller},
                    acceptor_loop(Kernel, Listener, maps:remove(SpawnedPid, Pending));
                {waiting, _} ->
                    %% Already waiting (shouldn't happen), replace
                    acceptor_loop(
                        Kernel, Listener, maps:put(SpawnedPid, {waiting, DistCtrl}, Pending)
                    )
            end;
        {_From, {accept_pending, _Controller, _MyNode, _Allowed, _SetupTime}} ->
            %% Connection pending, continue
            acceptor_loop(Kernel, Listener, Pending);
        stop ->
            ok;
        _Other ->
            acceptor_loop(Kernel, Listener, Pending)
    end.

%%====================================================================
%% Internal Functions - Accept Connection
%%====================================================================

%% @private
do_accept_connection(AcceptPid, DistCtrl, MyNode, Allowed, SetupTime, Kernel) ->
    %% Trap exits so we can handle the setup timer timeout properly
    process_flag(trap_exit, true),
    error_logger:info_msg("do_accept_connection: waiting for controller message from ~p~n", [
        AcceptPid
    ]),
    receive
        {AcceptPid, controller} ->
            error_logger:info_msg(
                "do_accept_connection: got controller, starting handshake. MyNode=~p, Kernel=~p~n",
                [MyNode, Kernel]
            ),
            Timer = dist_util:start_timer(SetupTime),
            HSData = create_hs_data(DistCtrl, MyNode, Timer, Allowed, Kernel),
            error_logger:info_msg(
                "do_accept_connection: HSData created, kernel_pid=~p~n",
                [HSData#hs_data.kernel_pid]
            ),
            try
                Result = dist_util:handshake_other_started(HSData),
                error_logger:info_msg("do_accept_connection: handshake result: ~p~n", [Result]),
                Result
            catch
                Class:Reason:Stack ->
                    error_logger:error_msg(
                        "do_accept_connection: handshake crashed: ~p:~p~n~p~n",
                        [Class, Reason, Stack]
                    ),
                    erlang:raise(Class, Reason, Stack)
            end
    after 5000 ->
        error_logger:error_msg("do_accept_connection: TIMEOUT waiting for controller from ~p~n", [
            AcceptPid
        ]),
        exit(controller_timeout)
    end.

%%====================================================================
%% Internal Functions - Setup Outgoing Connection
%%====================================================================

%% @private
%% Set up outgoing connection to a node.
do_setup(Kernel, Node, Type, MyNode, LongOrShortNames, SetupTime) ->
    %% Trap exits so we can handle the setup timer timeout properly
    process_flag(trap_exit, true),

    %% Ensure quic application is started
    case ensure_quic_started() of
        ok -> ok;
        {error, AppReason} -> ?shutdown2(Node, {quic_app_start_failed, AppReason})
    end,

    %% Start setup timer
    Timer = dist_util:start_timer(SetupTime),

    %% Parse target node name
    case parse_node_name(Node, LongOrShortNames) of
        {ok, Host} ->
            %% Look up node address via discovery
            case discover_node(Node, Host) of
                {ok, IP, Port} ->
                    connect_to_node(Kernel, Node, IP, Port, MyNode, Type, Timer);
                {error, Reason} ->
                    ?shutdown2(Node, {discovery_failed, Reason})
            end;
        {error, Reason} ->
            ?shutdown2(Node, Reason)
    end.

%% @private
parse_node_name(Node, LongOrShortNames) ->
    case dist_util:split_node(Node) of
        {node, Name, Host} when Name =/= "", Host =/= "" ->
            case LongOrShortNames of
                shortnames ->
                    %% Short name - host should not have dots
                    case lists:member($., Host) of
                        true -> {error, shortnames_with_fqdn};
                        false -> {ok, Host}
                    end;
                longnames ->
                    {ok, Host}
            end;
        {host, _Host} ->
            {error, invalid_node_name};
        _ ->
            {error, invalid_node_name}
    end.

%% @private
%% Discover node address using configured discovery module.
discover_node(Node, Host) ->
    Config = load_config(),
    DiscoveryModule = Config#quic_dist_config.discovery_module,

    %% First check static configuration
    case lists:keyfind(Node, 1, Config#quic_dist_config.nodes) of
        {Node, {IP, Port}} when is_tuple(IP) ->
            {ok, IP, Port};
        {Node, {IPStr, Port}} when is_list(IPStr) ->
            case inet:parse_address(IPStr) of
                {ok, IP} -> {ok, IP, Port};
                _ -> resolve_and_lookup(DiscoveryModule, Node, Host)
            end;
        false ->
            resolve_and_lookup(DiscoveryModule, Node, Host)
    end.

%% @private
resolve_and_lookup(DiscoveryModule, Node, Host) ->
    %% Try discovery module
    case code:ensure_loaded(DiscoveryModule) of
        {module, DiscoveryModule} ->
            case DiscoveryModule:lookup(Node, Host) of
                {ok, {IP, Port}} ->
                    {ok, IP, Port};
                {error, not_found} ->
                    %% Fall back to DNS resolution with default port
                    resolve_host(Host);
                Error ->
                    Error
            end;
        _ ->
            %% Discovery module not available, use DNS
            resolve_host(Host)
    end.

%% @private
resolve_host(Host) ->
    case inet:getaddr(Host, inet) of
        {ok, IP} ->
            {ok, IP, ?QUIC_DIST_DEFAULT_PORT};
        {error, _} ->
            case inet:getaddr(Host, inet6) of
                {ok, IP} ->
                    {ok, IP, ?QUIC_DIST_DEFAULT_PORT};
                Error ->
                    Error
            end
    end.

%% @private
%% Convert IP address to host string for QUIC connect.
%% Handles IP tuples, binary strings, and list strings.
ip_to_host(IP) when is_tuple(IP) ->
    inet:ntoa(IP);
ip_to_host(IP) when is_binary(IP) ->
    binary_to_list(IP);
ip_to_host(IP) when is_list(IP) ->
    IP.

%% @private
%% Connect to the target node.
connect_to_node(Kernel, Node, IP, Port, MyNode, Type, Timer) ->
    Config = load_config(),

    %% Prepare QUIC connection options
    case load_credentials(Config) of
        {ok, Cert, Key, _CACert} ->
            CongestionThreshold = Config#quic_dist_config.congestion_threshold,
            Opts = #{
                cert => Cert,
                key => Key,
                alpn => [?QUIC_DIST_ALPN],
                idle_timeout => ?QUIC_DIST_IDLE_TIMEOUT,
                %% Use higher initial cwnd for distribution bulk transfers
                initial_window => ?INITIAL_WINDOW_DISTRIBUTION,
                %% Keep a higher congestion floor to avoid liveness stalls
                %% on bursty virtual networks (e.g., Docker bridge).
                minimum_window => ?MINIMUM_WINDOW_DISTRIBUTION,
                %% Higher flow control limits for distribution to avoid blocking
                %% during large message transfers (code loading, large terms)
                max_data => ?DIST_INITIAL_MAX_DATA,
                max_stream_data_bidi_local => ?DIST_INITIAL_MAX_STREAM_DATA,
                max_stream_data_bidi_remote => ?DIST_INITIAL_MAX_STREAM_DATA,
                max_stream_data_uni => ?DIST_INITIAL_MAX_STREAM_DATA,
                %% Backpressure threshold for congestion detection
                congestion_threshold => CongestionThreshold,
                % TODO: Enable proper verification
                verify => false
            },

            %% Convert IP to host format expected by QUIC
            Host = ip_to_host(IP),

            %% Attempt connection
            case quic:connect(Host, Port, Opts, self()) of
                {ok, ConnRef} ->
                    %% Wait for connection to be established
                    wait_for_connection(Kernel, Node, ConnRef, MyNode, Type, Timer);
                {error, Reason} ->
                    ?shutdown2(Node, {connect_failed, Reason})
            end;
        {error, Reason} ->
            ?shutdown2(Node, {credentials, Reason})
    end.

%% @private
wait_for_connection(Kernel, Node, ConnRef, MyNode, Type, Timer) ->
    receive
        {quic, ConnRef, {connected, _Info}} ->
            %% Start distribution controller
            case quic_dist_controller:start_link(ConnRef, client) of
                {ok, DistCtrl} ->
                    %% Set kernel on controller and store node
                    quic_dist_controller:set_supervisor(DistCtrl, Kernel),
                    quic_dist_controller:set_node(DistCtrl, Node),
                    %% Perform distribution handshake
                    HSData = create_hs_data_setup(Kernel, DistCtrl, Node, MyNode, Type, Timer),
                    dist_util:handshake_we_started(HSData);
                {error, Reason} ->
                    quic:close(ConnRef, normal),
                    ?shutdown2(Node, {controller_failed, Reason})
            end;
        {quic, ConnRef, {closed, Reason}} ->
            ?shutdown2(Node, {closed, Reason});
        {quic, ConnRef, {transport_error, Code, Reason}} ->
            ?shutdown2(Node, {transport_error, Code, Reason});
        {'EXIT', Timer, setup_timer_timeout} ->
            quic:close(ConnRef, timeout),
            ?shutdown2(Node, connect_timeout)
    end.

%%====================================================================
%% Internal Functions - Handshake Data
%%====================================================================

%% @private
%% Create handshake data structure for accepted connections.
create_hs_data(DistCtrl, MyNode, Timer, Allowed, Kernel) ->
    %% Capture SetupPid (self) for dist_ctrlr message
    SetupPid = self(),
    error_logger:info_msg(
        "create_hs_data: Kernel=~p, DistCtrl=~p, SetupPid=~p~n",
        [Kernel, DistCtrl, SetupPid]
    ),
    #hs_data{
        kernel_pid = Kernel,
        other_node = undefined,
        this_node = MyNode,
        socket = DistCtrl,
        timer = Timer,
        this_flags = 0,
        other_flags = 0,
        f_send = fun(Ctrl, Data) -> quic_dist_controller:send(Ctrl, Data) end,
        f_recv = fun(Ctrl, Len, Timeout) ->
            %% Receive data and try to extract node name if this is the name message
            Result = quic_dist_controller:recv(Ctrl, Len, Timeout),
            case Result of
                {ok, Data} ->
                    %% Try to parse name message and store node in controller
                    maybe_extract_node(Data, Ctrl),
                    Result;
                _ ->
                    Result
            end
        end,
        f_setopts_pre_nodeup = fun(Ctrl) ->
            %% Just log and return ok - inet_tcp_dist doesn't do anything special here
            StoredNode = get_stored_node(Ctrl),
            error_logger:info_msg(
                "f_setopts_pre_nodeup (accept): Ctrl=~p, Node=~p, SetupPid=~p, linked=~p~n",
                [
                    Ctrl,
                    StoredNode,
                    SetupPid,
                    lists:member(Ctrl, element(2, process_info(self(), links)))
                ]
            ),
            ok
        end,
        f_setopts_post_nodeup = fun(_Ctrl) -> ok end,
        f_getll = fun(Ctrl) -> {ok, Ctrl} end,
        f_address = fun(Ctrl, Node) ->
            quic_dist_controller:get_address(Ctrl, Node)
        end,
        mf_tick = fun(Ctrl) -> quic_dist_controller:tick(Ctrl) end,
        mf_getstat = fun(Ctrl) -> quic_dist_controller:getstat(Ctrl) end,
        request_type = normal,
        mf_setopts = fun(_Ctrl, _Opts) -> ok end,
        mf_getopts = fun(_Ctrl, Opts) -> {ok, [{O, 0} || O <- Opts]} end,
        allowed = Allowed,
        f_handshake_complete = fun(Ctrl, HsNode, DHandle) ->
            error_logger:info_msg(
                "f_handshake_complete (accept): Ctrl=~p, Node=~p, DHandle=~p~n",
                [Ctrl, HsNode, DHandle]
            ),
            %% Notify controller that handshake is complete
            %% Pass DHandle so controller can use dist_ctrl_* functions
            Ctrl ! {handshake_complete, HsNode, DHandle},
            ok
        end
    }.

%% @private
%% Try to extract node name from name message and store in controller.
%% The name message format depends on protocol version:
%% Protocol 6: <<$N, Flags:64/big, Creation:32/big, NameLen:16/big, Name/binary>>
%% Older: <<$n, Version:16/big, Flags:32/big, Name/binary>>
maybe_extract_node([H | Rest], Ctrl) when H =:= $N; H =:= $n ->
    try
        case H of
            $N ->
                %% Protocol version 6 format
                RestBin = list_to_binary(Rest),
                <<_Flags:64/big, _Creation:32/big, NameLen:16/big, NameBin:NameLen/binary,
                    _/binary>> = RestBin,
                Node = binary_to_atom(NameBin, utf8),
                quic_dist_controller:set_node(Ctrl, Node);
            $n ->
                %% Older protocol format
                RestBin = list_to_binary(Rest),
                <<_Version:16/big, _Flags:32/big, NameBin/binary>> = RestBin,
                Node = binary_to_atom(NameBin, utf8),
                quic_dist_controller:set_node(Ctrl, Node)
        end
    catch
        _:_ ->
            %% Failed to parse, not a name message or malformed
            ok
    end;
maybe_extract_node(_, _) ->
    ok.

%% @private
%% Get the stored node from controller, with fallback.
get_stored_node(Ctrl) ->
    case quic_dist_controller:get_node(Ctrl) of
        {ok, Node} -> Node;
        undefined -> undefined
    end.

%% @private
%% Create handshake data structure for outgoing connections.
create_hs_data_setup(Kernel, DistCtrl, Node, MyNode, Type, Timer) ->
    %% Capture SetupPid (self) for dist_ctrlr message
    SetupPid = self(),
    error_logger:info_msg(
        "create_hs_data_setup: Kernel=~p, DistCtrl=~p, Node=~p, SetupPid=~p~n",
        [Kernel, DistCtrl, Node, SetupPid]
    ),
    #hs_data{
        kernel_pid = Kernel,
        other_node = Node,
        this_node = MyNode,
        socket = DistCtrl,
        timer = Timer,
        this_flags = 0,
        other_flags = 0,
        f_send = fun(Ctrl, Data) -> quic_dist_controller:send(Ctrl, Data) end,
        f_recv = fun(Ctrl, Len, Timeout) -> quic_dist_controller:recv(Ctrl, Len, Timeout) end,
        f_setopts_pre_nodeup = fun(Ctrl) ->
            %% Just log and return ok - inet_tcp_dist doesn't do anything special here
            error_logger:info_msg(
                "f_setopts_pre_nodeup (setup): Ctrl=~p, Node=~p, SetupPid=~p, linked=~p~n",
                [Ctrl, Node, SetupPid, lists:member(Ctrl, element(2, process_info(self(), links)))]
            ),
            ok
        end,
        f_setopts_post_nodeup = fun(_Ctrl) -> ok end,
        f_getll = fun(Ctrl) -> {ok, Ctrl} end,
        f_address = fun(Ctrl, N) ->
            quic_dist_controller:get_address(Ctrl, N)
        end,
        mf_tick = fun(Ctrl) -> quic_dist_controller:tick(Ctrl) end,
        mf_getstat = fun(Ctrl) -> quic_dist_controller:getstat(Ctrl) end,
        request_type = Type,
        mf_setopts = fun(_Ctrl, _Opts) -> ok end,
        mf_getopts = fun(_Ctrl, Opts) -> {ok, [{O, 0} || O <- Opts]} end,
        f_handshake_complete = fun(Ctrl, HsNode, DHandle) ->
            error_logger:info_msg(
                "f_handshake_complete (setup): Ctrl=~p, Node=~p, DHandle=~p~n",
                [Ctrl, HsNode, DHandle]
            ),
            %% Notify controller that handshake is complete
            %% Pass DHandle so controller can use dist_ctrl_* functions
            Ctrl ! {handshake_complete, HsNode, DHandle},
            ok
        end
    }.
