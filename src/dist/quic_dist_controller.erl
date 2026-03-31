%%% -*- erlang -*-
%%%
%%% QUIC Distribution Controller
%%% Per-connection controller for Erlang distribution over QUIC
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Per-connection distribution controller.
%%%
%%% This module manages a single distribution connection over QUIC,
%%% handling:
%%%
%%% - Control stream (stream 0) for handshake and tick messages
%%% - Data stream pool for distribution messages
%%% - Message framing with length prefixes
%%% - Tick handling for connection liveness
%%% - Stream prioritization
%%%
%%% == Stream Layout ==
%%%
%%% Stream 0: Control (urgency 0)
%%%   - Distribution handshake messages
%%%   - Tick messages
%%%   - Link/monitor signals
%%%
%%% Streams 4,8,12...: Data (urgency 4-6)
%%%   - Regular distribution messages
%%%   - Round-robin scheduling
%%%
%%% @end

-module(quic_dist_controller).
-behaviour(gen_statem).

-include("quic_dist.hrl").
-include_lib("kernel/include/net_address.hrl").
-include_lib("kernel/include/logger.hrl").

-define(QUIC_LOG_META, #{
    domain => [erlang_quic, dist_controller], report_cb => fun quic_log:format_report/2
}).

%% Maximum messages to deliver per batch in input handler before yielding.
%% Prevents blocking on dist_ctrl_put_data during heavy incoming traffic.
-define(INPUT_HANDLER_BATCH_SIZE, 32).

%% API
-export([
    start_link/2,
    start_link/3,
    send/2,
    recv/3,
    tick/1,
    getstat/1,
    get_address/2,
    set_supervisor/2,
    set_node/2,
    get_node/1,
    getll/1,
    pre_nodeup/1
]).

%% gen_statem callbacks
-export([
    init/1,
    callback_mode/0,
    terminate/3,
    code_change/4
]).

%% State functions
-export([
    init_state/3,
    handshaking/3,
    connected/3
]).

%% Internal state
-record(state, {
    %% Connection
    conn_ref :: reference(),
    conn_pid :: pid() | undefined,
    role :: client | server,

    %% Streams
    control_stream :: non_neg_integer() | undefined,
    data_streams = [] :: [non_neg_integer()],
    data_stream_idx = 0 :: non_neg_integer(),

    %% Receive buffer for control stream (handshake only)
    recv_buffer = <<>> :: binary(),
    recv_queue = queue:new() :: queue:queue(),
    recv_waiters = [] :: [{pid(), reference(), non_neg_integer()}],

    %% Pending data stream buffer (for data arriving before connected state)
    %% This handles the race where peer sends distribution data before we
    %% have finished transitioning to connected state with input handler
    pending_data_buffer = <<>> :: binary(),

    %% Send queue for pending messages
    send_queue = queue:new() :: queue:queue(),

    %% Supervision
    supervisor :: pid() | undefined,
    kernel :: pid() | undefined,

    %% Remote node info
    node :: node() | undefined,

    %% Tick handling
    tick_time :: non_neg_integer() | undefined,
    tick_ref :: reference() | undefined,

    %% Distribution handle (from erlang:setnode)
    dhandle :: term() | undefined,
    input_handler :: pid() | undefined,

    %% Statistics
    recv_cnt = 0 :: non_neg_integer(),
    send_cnt = 0 :: non_neg_integer(),
    recv_oct = 0 :: non_neg_integer(),
    send_oct = 0 :: non_neg_integer(),

    %% Session ticket for 0-RTT
    session_ticket :: term() | undefined,

    %% Backpressure tuning (from quic_dist_config or defaults)
    max_pull = ?DEFAULT_MAX_PULL_PER_NOTIFICATION :: pos_integer(),
    backpressure_retry = ?DEFAULT_BACKPRESSURE_RETRY_MS :: pos_integer()
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Start a controller for a client connection.
-spec start_link(ConnRef :: reference(), Role :: client) ->
    {ok, pid()} | {error, term()}.
start_link(ConnRef, client = Role) ->
    gen_statem:start_link(?MODULE, {ConnRef, Role}, []).

%% @doc Start a controller for a server connection.
-spec start_link(ConnPid :: pid(), ConnRef :: reference(), Role :: server) ->
    {ok, pid()} | {error, term()}.
start_link(ConnPid, ConnRef, server = Role) ->
    gen_statem:start_link(?MODULE, {ConnPid, ConnRef, Role}, []).

%% @doc Send data on the control stream.
-spec send(Controller :: pid(), Data :: iodata()) -> ok | {error, term()}.
send(Controller, Data) ->
    gen_statem:call(Controller, {send, Data}).

%% @doc Receive data from the control stream.
-spec recv(
    Controller :: pid(),
    Length :: non_neg_integer(),
    Timeout :: timeout()
) ->
    {ok, [byte()]} | {error, term()}.
recv(Controller, Length, Timeout) ->
    gen_statem:call(Controller, {recv, Length}, Timeout).

%% @doc Send a tick message.
-spec tick(Controller :: pid()) -> ok.
tick(Controller) ->
    gen_statem:cast(Controller, tick).

%% @doc Get connection statistics.
-spec getstat(Controller :: pid()) ->
    {ok, RecvCnt :: non_neg_integer(), SendCnt :: non_neg_integer(), SendPend :: non_neg_integer()}.
getstat(Controller) ->
    gen_statem:call(Controller, getstat).

%% @doc Get address information for the connection.
-spec get_address(Controller :: pid(), Node :: node()) ->
    {ok, #net_address{}}.
get_address(Controller, Node) ->
    gen_statem:call(Controller, {get_address, Node}).

%% @doc Set the supervisor process (kernel).
-spec set_supervisor(Controller :: pid(), Supervisor :: pid()) -> ok.
set_supervisor(Controller, Supervisor) ->
    gen_statem:cast(Controller, {set_supervisor, Supervisor}).

%% @doc Set the other node name.
-spec set_node(Controller :: pid(), Node :: node()) -> ok.
set_node(Controller, Node) ->
    gen_statem:cast(Controller, {set_node, Node}).

%% @doc Get the other node name.
-spec get_node(Controller :: pid()) -> {ok, node()} | undefined.
get_node(Controller) ->
    gen_statem:call(Controller, get_node).

%% @doc Get low-level controller (self).
-spec getll(Controller :: pid()) -> {ok, pid()}.
getll(Controller) ->
    gen_statem:call(Controller, getll).

%% @doc Pre-nodeup callback - sends dist_ctrlr message to kernel.
%% Called by f_setopts_pre_nodeup. SetupPid is the calling process.
-spec pre_nodeup(Controller :: pid()) -> ok.
pre_nodeup(Controller) ->
    gen_statem:call(Controller, {pre_nodeup, self()}).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() ->
    [state_functions, state_enter].

%% Initialize for client role
init({ConnRef, client}) ->
    %% Lookup connection PID
    case quic_connection:lookup(ConnRef) of
        {ok, ConnPid} ->
            State = init_backpressure_config(#state{
                conn_ref = ConnRef,
                conn_pid = ConnPid,
                role = client
            }),
            {ok, init_state, State};
        error ->
            {stop, connection_not_found}
    end;
%% Initialize for server role
init({ConnPid, ConnRef, server}) ->
    State = init_backpressure_config(#state{
        conn_ref = ConnRef,
        conn_pid = ConnPid,
        role = server
    }),
    {ok, init_state, State}.

%% @private
%% Initialize backpressure configuration from application environment.
%% Reads max_pull_per_notification and backpressure_retry_ms from quic dist config.
init_backpressure_config(State) ->
    DistOpts = application:get_env(quic, dist, []),
    MaxPull = get_dist_opt(max_pull_per_notification, DistOpts, ?DEFAULT_MAX_PULL_PER_NOTIFICATION),
    RetryMs = get_dist_opt(backpressure_retry_ms, DistOpts, ?DEFAULT_BACKPRESSURE_RETRY_MS),
    State#state{
        max_pull = MaxPull,
        backpressure_retry = RetryMs
    }.

%% @private
%% Get option from dist config (supports both proplist and map).
get_dist_opt(Key, Opts, Default) when is_list(Opts) ->
    proplists:get_value(Key, Opts, Default);
get_dist_opt(Key, Opts, Default) when is_map(Opts) ->
    maps:get(Key, Opts, Default).

terminate(_Reason, _StateName, #state{conn_ref = ConnRef}) ->
    try
        quic:close(ConnRef, normal)
    catch
        _:_ -> ok
    end,
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%====================================================================
%% State: init_state
%%====================================================================

init_state(enter, _OldState, #state{role = client, conn_ref = ConnRef} = State) ->
    %% Client: connection is already established (we received connected message)
    %% Take over ownership synchronously to ensure we receive stream_data messages
    ok = quic:set_owner_sync(ConnRef, self()),
    %% Can proceed to open streams immediately
    case setup_streams(State) of
        {ok, State1} ->
            {keep_state, State1, [{state_timeout, 0, start_handshake}]};
        {error, Reason} ->
            {stop, {stream_setup_failed, Reason}}
    end;
init_state(enter, _OldState, #state{role = server, conn_ref = ConnRef} = State) ->
    %% Server: take ownership synchronously and proceed immediately
    %% The connection_handler callback is called during QUIC handshake,
    %% and the listener transfers ownership to us. We don't need to wait
    %% for {connected, _} since we use stream 0 (client-initiated).
    case quic_connection:lookup(ConnRef) of
        {ok, ConnPid} ->
            %% Take over as owner synchronously to ensure we receive stream_data
            ok = quic:set_owner_sync(ConnRef, self()),
            State1 = State#state{conn_pid = ConnPid},
            %% Setup streams - transition via timeout since enter can't change state
            case setup_streams(State1) of
                {ok, State2} ->
                    {keep_state, State2, [{state_timeout, 0, proceed_to_handshaking}]};
                {error, Reason} ->
                    {stop, {stream_setup_failed, Reason}}
            end;
        error ->
            {stop, connection_not_found}
    end;
%% Server proceeds to handshaking after setup
init_state(state_timeout, proceed_to_handshaking, State) ->
    {next_state, handshaking, State};
%% Server receives connected message - just ignore, we already transitioned
init_state(info, {quic, ConnRef, {connected, _Info}}, #state{conn_ref = ConnRef} = State) ->
    {keep_state, State};
init_state(state_timeout, start_handshake, State) ->
    {next_state, handshaking, State};
%% Handle QUIC errors during init
init_state(info, {quic, ConnRef, {closed, Reason}}, #state{conn_ref = ConnRef}) ->
    {stop, {connection_closed, Reason}};
init_state(info, {quic, ConnRef, {transport_error, Code, Reason}}, #state{conn_ref = ConnRef}) ->
    {stop, {transport_error, Code, Reason}};
init_state(EventType, Event, State) ->
    handle_common_event(EventType, Event, init_state, State).

%% @private
%% Set up control and data streams once connection is ready.
setup_streams(#state{role = client} = State) ->
    %% Client opens streams and sets priorities
    case open_control_stream(State) of
        {ok, StreamId, State1} ->
            %% Set stream priority (highest for control)
            case set_stream_priority(State1, StreamId, ?QUIC_DIST_URGENCY_CONTROL) of
                ok ->
                    State2 = State1#state{control_stream = StreamId},
                    %% Open data streams
                    open_data_streams(State2, ?QUIC_DIST_DATA_STREAMS);
                {error, Reason} ->
                    {error, {priority_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {control_stream_failed, Reason}}
    end;
setup_streams(#state{role = server} = State) ->
    %% Server uses stream 0 (opened by client) for control
    %% We don't set priority on streams we don't own
    %% Server-initiated data streams (1, 5, 9, ...) will be opened later if needed
    State1 = State#state{control_stream = 0},
    {ok, State1}.

%%====================================================================
%% State: handshaking
%%====================================================================

handshaking(enter, _OldState, _State) ->
    keep_state_and_data;
%% Handle tick during handshake - send empty frame to keep connection alive
handshaking(cast, tick, State) ->
    send_tick_frame(State),
    {keep_state, State};
%% Handle send during handshake
handshaking({call, From}, {send, Data}, State) ->
    case do_send_control(Data, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            ?LOG_WARNING(#{what => handshake_send_failed, reason => Reason}, ?QUIC_LOG_META),
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
%% Handle recv during handshake
handshaking({call, From}, {recv, Length}, State) ->
    case try_recv(Length, State) of
        {ok, Data, State1} ->
            %% dist_util expects data as a list (charlist), not binary
            DataList = binary_to_list(Data),
            {keep_state, State1, [{reply, From, {ok, DataList}}]};
        {need_more, State1} ->
            %% Queue the waiter
            Ref = make_ref(),
            Waiters = [{From, Ref, Length} | State1#state.recv_waiters],
            {keep_state, State1#state{recv_waiters = Waiters}}
    end;
%% Handshake complete notification with DHandle
handshaking(info, {handshake_complete, Node, DHandle}, State) ->
    ?LOG_INFO(#{what => handshake_complete, node => Node}, ?QUIC_LOG_META),

    %% Set up distribution control machinery
    %% This is required for process-based distribution to work properly

    %% Server needs to open data streams too (server-initiated: 1, 5, 9, ...)
    State0 =
        case State#state.role of
            server -> open_server_data_streams(State);
            client -> State
        end,

    %% Spawn input handler to receive QUIC data and deliver to VM
    Self = self(),
    ConnRef = State0#state.conn_ref,
    ControlStream = State0#state.control_stream,
    InputHandler = spawn_link(
        fun() ->
            input_handler_loop(DHandle, Self, ConnRef, ControlStream)
        end
    ),

    %% Register input handler with VM
    ok = erlang:dist_ctrl_input_handler(DHandle, InputHandler),

    %% DON'T notify here - wait until we're in connected state
    %% The notification happens in the connected state's enter callback

    State1 = State0#state{
        node = Node,
        dhandle = DHandle,
        input_handler = InputHandler
    },
    {next_state, connected, State1};
%% Legacy handshake complete notification (for backward compatibility)
handshaking(info, {handshake_complete, Node}, State) ->
    ?LOG_WARNING(#{what => handshake_complete_no_dhandle, node => Node}, ?QUIC_LOG_META),
    State1 = State#state{node = Node},
    {next_state, connected, State1};
handshaking(EventType, Event, State) ->
    handle_common_event(EventType, Event, handshaking, State).

%%====================================================================
%% State: connected
%%====================================================================

connected(
    enter, _OldState, #state{role = server, data_streams = [], dhandle = DHandle} = State
) when
    DHandle =/= undefined
->
    %% Server needs to open data streams for sending distribution data
    NewState = open_server_data_streams(State),
    %% Forward any pending data stream content to input handler
    NewState2 = forward_pending_data(NewState),
    %% Notify VM we're ready for data
    erlang:dist_ctrl_get_data_notification(DHandle),
    {keep_state, NewState2};
connected(enter, _OldState, #state{dhandle = DHandle} = State) when DHandle =/= undefined ->
    %% Client already has data streams, just notify VM we're ready
    %% Forward any pending data stream content to input handler
    NewState = forward_pending_data(State),
    erlang:dist_ctrl_get_data_notification(DHandle),
    {keep_state, NewState};
connected(enter, _OldState, _State) ->
    %% No DHandle (shouldn't happen in normal flow)
    keep_state_and_data;
%% Handle send in connected state (direct send, not from VM)
connected({call, From}, {send, Data}, State) ->
    case do_send_data(Data, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;
%% Handle recv in connected state (for backward compatibility)
connected({call, From}, {recv, Length}, State) ->
    case try_recv(Length, State) of
        {ok, Data, State1} ->
            DataList = binary_to_list(Data),
            {keep_state, State1, [{reply, From, {ok, DataList}}]};
        {need_more, State1} ->
            Ref = make_ref(),
            Waiters = [{From, Ref, Length} | State1#state.recv_waiters],
            {keep_state, State1#state{recv_waiters = Waiters}}
    end;
%% Handle tick (from mf_tick callback)
%% CRITICAL: Always send tick frame FIRST as the liveness signal.
%% The tick frame uses the control stream (urgency 0, separate flow control)
%% to ensure it gets through even when data streams are congested.
%% Then optionally flush limited data (best effort, not blocking).
connected(cast, tick, #state{dhandle = DHandle, conn_ref = ConnRef} = State) when
    DHandle =/= undefined
->
    %% ALWAYS send tick frame first - this is the liveness signal
    send_tick_frame(State),
    %% Then try to flush some data if not congested (best effort)
    case quic:get_send_queue_info(ConnRef) of
        {ok, #{congested := false}} ->
            _ = send_dist_data_with_tick(State);
        _ ->
            ok
    end,
    {keep_state, State};
connected(cast, tick, State) ->
    %% No DHandle yet, send empty frame to keep QUIC connection alive
    send_tick_frame(State),
    {keep_state, State};
%% Handle dist_data notification from VM
%% This means the VM has data ready for us to send
%% Uses backpressure to avoid overwhelming the QUIC send queue
connected(
    info,
    dist_data,
    #state{dhandle = DHandle, conn_ref = ConnRef, backpressure_retry = RetryMs} = State
) when
    DHandle =/= undefined
->
    case quic:get_send_queue_info(ConnRef) of
        {ok, #{congested := true}} ->
            %% Queue is congested - don't pull more data
            %% Re-check after a delay
            erlang:send_after(RetryMs, self(), check_queue),
            {keep_state, State};
        {ok, #{congested := false}} ->
            %% Queue has room - pull and send limited amount of data
            send_dist_data_limited(State),
            %% Re-register for next notification
            erlang:dist_ctrl_get_data_notification(DHandle),
            {keep_state, State};
        {error, _} ->
            %% Error getting info - try sending anyway to avoid deadlock
            send_dist_data_limited(State),
            erlang:dist_ctrl_get_data_notification(DHandle),
            {keep_state, State}
    end;
%% Handle check_queue - retry sending after backpressure delay
connected(
    info,
    check_queue,
    #state{dhandle = DHandle, conn_ref = ConnRef, backpressure_retry = RetryMs} = State
) when
    DHandle =/= undefined
->
    case quic:get_send_queue_info(ConnRef) of
        {ok, #{congested := false}} ->
            %% Queue has room - pull and send data
            send_dist_data_limited(State),
            erlang:dist_ctrl_get_data_notification(DHandle),
            {keep_state, State};
        _ ->
            %% Still congested or error - retry later
            erlang:send_after(RetryMs, self(), check_queue),
            {keep_state, State}
    end;
connected(EventType, Event, State) ->
    handle_common_event(EventType, Event, connected, State).

%%====================================================================
%% Common Event Handling
%%====================================================================

handle_common_event({call, From}, getstat, _StateName, State) ->
    #state{recv_cnt = RecvCnt, send_cnt = SendCnt} = State,
    SendPend = queue:len(State#state.send_queue),
    {keep_state, State, [{reply, From, {ok, RecvCnt, SendCnt, SendPend}}]};
handle_common_event(
    {call, From},
    {get_address, Node},
    _StateName,
    #state{conn_ref = ConnRef} = State
) ->
    Address =
        case quic:peername(ConnRef) of
            {ok, {IP, Port}} ->
                #net_address{
                    address = {IP, Port},
                    host = atom_to_list(Node),
                    protocol = quic,
                    family = inet
                };
            _Error ->
                #net_address{
                    address = undefined,
                    host = atom_to_list(Node),
                    protocol = quic,
                    family = inet
                }
        end,
    {keep_state, State, [{reply, From, {ok, Address}}]};
handle_common_event(cast, {set_supervisor, Pid}, _StateName, State) ->
    %% Store both as supervisor and kernel (net_kernel)
    {keep_state, State#state{supervisor = Pid, kernel = Pid}};
handle_common_event(cast, {set_node, Node}, _StateName, State) ->
    {keep_state, State#state{node = Node}};
handle_common_event({call, From}, get_node, _StateName, #state{node = Node} = State) ->
    Reply =
        case Node of
            undefined -> undefined;
            _ -> {ok, Node}
        end,
    {keep_state, State, [{reply, From, Reply}]};
handle_common_event({call, From}, getll, _StateName, State) ->
    {keep_state, State, [{reply, From, {ok, self()}}]};
handle_common_event(
    {call, From},
    {pre_nodeup, SetupPid},
    _StateName,
    #state{kernel = Kernel, node = Node} = State
) ->
    %% Send dist_ctrlr message to kernel to register this controller
    %% This is required before mark_nodeup can succeed
    case {Kernel, Node} of
        {undefined, _} ->
            ?LOG_WARNING(#{what => pre_nodeup_no_kernel}, ?QUIC_LOG_META),
            {keep_state, State, [{reply, From, ok}]};
        {_, undefined} ->
            ?LOG_WARNING(#{what => pre_nodeup_no_node}, ?QUIC_LOG_META),
            {keep_state, State, [{reply, From, ok}]};
        {K, N} when is_pid(K), is_atom(N) ->
            K ! {dist_ctrlr, self(), N, SetupPid},
            {keep_state, State, [{reply, From, ok}]}
    end;
%% Handle incoming QUIC messages
handle_common_event(
    info,
    {quic, ConnRef, {stream_data, StreamId, Data, _Fin}},
    StateName,
    #state{
        conn_ref = ConnRef,
        control_stream = CtrlStream
    } = State
) ->
    case StreamId of
        CtrlStream ->
            %% Data on control stream
            handle_control_data(Data, StateName, State);
        _ ->
            %% Data on data stream
            handle_stream_data(StreamId, Data, StateName, State)
    end;
handle_common_event(
    info,
    {quic, ConnRef, {session_ticket, Ticket}},
    _StateName,
    #state{conn_ref = ConnRef} = State
) ->
    %% Store session ticket for 0-RTT
    {keep_state, State#state{session_ticket = Ticket}};
handle_common_event(
    info,
    {quic, ConnRef, {connected, _Info}},
    _StateName,
    #state{conn_ref = ConnRef} = State
) ->
    %% Connection fully established - we may receive this after transitioning
    %% to handshaking state, just acknowledge and continue
    {keep_state, State};
handle_common_event(
    info,
    {quic, ConnRef, {stream_opened, _StreamId}},
    _StateName,
    #state{conn_ref = ConnRef} = State
) ->
    %% New stream opened by peer - for distribution, we primarily use stream 0
    {keep_state, State};
handle_common_event(
    info,
    {quic, ConnRef, {closed, Reason}},
    _StateName,
    #state{conn_ref = ConnRef} = State
) ->
    %% Connection closed
    {stop, {connection_closed, Reason}, State};
handle_common_event(
    info,
    {quic, ConnRef, {transport_error, Code, Reason}},
    _StateName,
    #state{conn_ref = ConnRef} = State
) ->
    {stop, {transport_error, Code, Reason}, State};
handle_common_event(
    info,
    {quic, _OtherRef, {stream_data, StreamId, Data, _Fin}},
    _StateName,
    State
) ->
    %% Stream data with non-matching ConnRef (should not happen)
    ?LOG_WARNING(
        #{
            what => stream_data_conn_mismatch,
            stream_id => StreamId,
            data_size => byte_size(Data)
        },
        ?QUIC_LOG_META
    ),
    {keep_state, State};
%% Handle tick in any state (fallback)
handle_common_event(cast, tick, _StateName, State) ->
    send_tick_frame(State),
    {keep_state, State};
handle_common_event(_EventType, _Event, _StateName, State) ->
    {keep_state, State}.

%%====================================================================
%% Internal Functions - Streams
%%====================================================================

%% @private
%% Open the control stream (client only - server uses stream 0 from client).
open_control_stream(#state{conn_ref = ConnRef} = State) ->
    case quic:open_stream(ConnRef) of
        {ok, StreamId} ->
            {ok, StreamId, State};
        Error ->
            Error
    end.

%% @private
%% Open data streams for message passing.
open_data_streams(State, 0) ->
    {ok, State};
open_data_streams(#state{conn_ref = ConnRef, data_streams = Streams} = State, N) ->
    case quic:open_stream(ConnRef) of
        {ok, StreamId} ->
            %% Set priority (lower than control, but reasonable)
            ok = set_stream_priority(State, StreamId, ?QUIC_DIST_URGENCY_DATA_NORMAL),
            open_data_streams(State#state{data_streams = [StreamId | Streams]}, N - 1);
        {error, Reason} ->
            %% Log but continue with available streams
            ?LOG_WARNING(#{what => open_data_stream_failed, reason => Reason}, ?QUIC_LOG_META),
            {ok, State}
    end.

%% @private
set_stream_priority(#state{conn_ref = ConnRef}, StreamId, Urgency) ->
    quic:set_stream_priority(ConnRef, StreamId, Urgency, false).

%% @private
%% Open server-initiated data streams after handshake.
%% Server-initiated bidirectional streams have IDs 1, 5, 9, ...
open_server_data_streams(State) ->
    {ok, NewState} = open_data_streams(State, ?QUIC_DIST_DATA_STREAMS),
    NewState.

%% @private
%% Forward any pending data stream content to the input handler.
%% This handles the race condition where the peer starts sending distribution
%% data before we've finished processing our handshake_complete message and
%% transitioning to connected state.
forward_pending_data(#state{pending_data_buffer = <<>>, input_handler = InputHandler} = State) when
    is_pid(InputHandler)
->
    %% No pending data
    State;
forward_pending_data(
    #state{pending_data_buffer = PendingData, input_handler = InputHandler} = State
) when
    is_pid(InputHandler), byte_size(PendingData) > 0
->
    %% Forward buffered data to input handler
    ?LOG_INFO(
        #{
            what => forwarding_pending_data,
            size => byte_size(PendingData)
        },
        ?QUIC_LOG_META
    ),
    InputHandler ! {dist_data, PendingData},
    State#state{pending_data_buffer = <<>>};
forward_pending_data(#state{pending_data_buffer = PendingData} = State) when
    byte_size(PendingData) > 0
->
    %% No input handler yet - this shouldn't happen but log warning
    ?LOG_WARNING(
        #{
            what => pending_data_no_handler,
            size => byte_size(PendingData)
        },
        ?QUIC_LOG_META
    ),
    State;
forward_pending_data(State) ->
    %% No pending data and no handler
    State.

%%====================================================================
%% Internal Functions - Send
%%====================================================================

%% @private
%% Send data on control stream (handshake messages).
%% Note: No framing needed - dist_util handles its own protocol framing.
do_send_control(
    Data,
    #state{
        conn_ref = ConnRef,
        control_stream = StreamId,
        send_cnt = SendCnt,
        send_oct = SendOct
    } = State
) ->
    DataBin = iolist_to_binary(Data),
    Len = byte_size(DataBin),

    case quic:send_data(ConnRef, StreamId, DataBin, false) of
        ok ->
            {ok, State#state{
                send_cnt = SendCnt + 1,
                send_oct = SendOct + Len
            }};
        Error ->
            Error
    end.

%% @private
%% Send data on a data stream (round-robin).
%% Note: No framing needed - dist_util handles its own protocol framing.
do_send_data(
    Data,
    #state{
        conn_ref = ConnRef,
        data_streams = Streams,
        data_stream_idx = Idx,
        send_cnt = SendCnt,
        send_oct = SendOct
    } = State
) when Streams =/= [] ->
    %% Select stream via round-robin
    StreamId = lists:nth((Idx rem length(Streams)) + 1, Streams),

    DataBin = iolist_to_binary(Data),
    Len = byte_size(DataBin),

    case quic:send_data(ConnRef, StreamId, DataBin, false) of
        ok ->
            {ok, State#state{
                data_stream_idx = Idx + 1,
                send_cnt = SendCnt + 1,
                send_oct = SendOct + Len
            }};
        Error ->
            Error
    end;
%% Fall back to control stream if no data streams
do_send_data(Data, State) ->
    do_send_control(Data, State).

%% @private
%% Send tick frame on control stream for priority delivery.
%% Control stream has urgency 0 and separate flow control from data streams.
%% This ensures ticks always get through even when data streams are blocked.
send_tick_frame(#state{conn_ref = ConnRef, control_stream = CtrlStream}) when
    CtrlStream =/= undefined
->
    %% Always use control stream first - highest priority, separate flow control
    quic:send_data(ConnRef, CtrlStream, <<0:32/big-unsigned>>, false),
    ok;
send_tick_frame(#state{conn_ref = ConnRef, data_streams = [FirstStream | _]}) ->
    %% Fallback to data stream only if no control stream
    quic:send_data(ConnRef, FirstStream, <<0:32/big-unsigned>>, false),
    ok;
send_tick_frame(_State) ->
    ok.

%% @private
%% Send distribution data from VM via QUIC with backpressure.
%% Called when dist_data notification is received.
%% Limits pulls to max_pull to prevent burst.
send_dist_data_limited(#state{
    dhandle = DHandle,
    conn_ref = ConnRef,
    data_streams = [FirstStream | _],
    max_pull = MaxPull
}) ->
    %% Use first data stream for all distribution data to maintain ordering
    send_dist_data_limited_loop(DHandle, ConnRef, FirstStream, MaxPull);
send_dist_data_limited(#state{
    dhandle = DHandle,
    conn_ref = ConnRef,
    control_stream = CtrlStream,
    max_pull = MaxPull
}) ->
    %% Fallback: no data streams, use control stream
    send_dist_data_limited_loop(DHandle, ConnRef, CtrlStream, MaxPull).

%% @private
%% Send distribution data with limited pulls per notification.
send_dist_data_limited_loop(_DHandle, _ConnRef, _StreamId, 0) ->
    %% Pulled enough for now
    ok;
send_dist_data_limited_loop(DHandle, ConnRef, StreamId, Remaining) ->
    case erlang:dist_ctrl_get_data(DHandle) of
        none ->
            ok;
        Data ->
            case send_one_frame(ConnRef, StreamId, Data) of
                ok ->
                    send_dist_data_limited_loop(DHandle, ConnRef, StreamId, Remaining - 1);
                {error, send_queue_full} ->
                    %% Stop pulling, queue is full
                    ok;
                {error, {flow_control_blocked, _}} ->
                    %% Flow control blocked - stop pulling to avoid data loss
                    %% Will retry when MAX_DATA/MAX_STREAM_DATA is received
                    ok;
                {error, _} ->
                    %% Other error - continue trying
                    send_dist_data_limited_loop(DHandle, ConnRef, StreamId, Remaining - 1)
            end
    end.

%% @private
%% Send distribution data, returning `sent` if data was sent, `none` if nothing.
%% Used by tick handler to flush limited data (best effort, not blocking).
%% Respects max_pull to prevent unbounded loop during tick callback.
send_dist_data_with_tick(#state{
    dhandle = DHandle,
    conn_ref = ConnRef,
    data_streams = [FirstStream | _],
    max_pull = MaxPull
}) ->
    send_dist_data_loop_tick(DHandle, ConnRef, FirstStream, none, MaxPull);
send_dist_data_with_tick(#state{
    dhandle = DHandle,
    conn_ref = ConnRef,
    control_stream = CtrlStream,
    max_pull = MaxPull
}) ->
    send_dist_data_loop_tick(DHandle, ConnRef, CtrlStream, none, MaxPull).

%% @private
%% Send distribution data with pull limit to prevent tick callback blocking.
send_dist_data_loop_tick(_DHandle, _ConnRef, _StreamId, Status, 0) ->
    %% Reached pull limit - stop to avoid blocking tick callback
    Status;
send_dist_data_loop_tick(DHandle, ConnRef, StreamId, Status, Remaining) ->
    case erlang:dist_ctrl_get_data(DHandle) of
        none ->
            Status;
        Data ->
            case send_one_frame(ConnRef, StreamId, Data) of
                ok ->
                    send_dist_data_loop_tick(DHandle, ConnRef, StreamId, sent, Remaining - 1);
                {error, {flow_control_blocked, _}} ->
                    %% Flow control blocked - stop to avoid data loss
                    Status;
                {error, _} ->
                    %% Other error - stop trying
                    Status
            end
    end.

%% @private
%% Send a single framed message.
%% Adds 4-byte big-endian length prefix for message framing over QUIC.
%% Returns ok on success or {error, Reason} on failure.
send_one_frame(ConnRef, StreamId, Data) ->
    %% dist_ctrl_get_data returns raw message data (no length prefix)
    %% We add 4-byte length prefix for framing over QUIC
    DataBin = iolist_to_binary(Data),
    Length = byte_size(DataBin),
    FramedData = <<Length:32/big-unsigned, DataBin/binary>>,
    case quic:send_data(ConnRef, StreamId, FramedData, false) of
        ok -> ok;
        {error, Reason} -> {error, Reason}
    end.

%%====================================================================
%% Input Handler - receives QUIC data and delivers to VM
%%====================================================================

%% @private
%% Input handler loop - receives QUIC data from controller and delivers to VM.
%% This runs in a separate process registered with erlang:dist_ctrl_input_handler.
%%
%% IMPORTANT: The distribution protocol uses 4-byte length-prefixed messages:
%%   <<Length:32/big-unsigned, Payload:Length/binary>>
%%
%% QUIC delivers data in arbitrary chunks (typically ~1100 bytes due to MTU).
%% We MUST buffer incoming data and only pass complete messages to the VM.
%% Passing partial messages causes "corrupted distribution header" errors.
input_handler_loop(DHandle, Controller, ConnRef, ControlStream) ->
    %% Start with empty buffer
    input_handler_loop(DHandle, Controller, ConnRef, ControlStream, <<>>).

input_handler_loop(DHandle, Controller, ConnRef, ControlStream, Buffer) ->
    receive
        {continue_delivery, PendingBuffer} ->
            %% Continue processing after batch yield
            case deliver_complete_messages(DHandle, PendingBuffer) of
                {ok, RemainingBuffer} ->
                    input_handler_loop(
                        DHandle, Controller, ConnRef, ControlStream, RemainingBuffer
                    );
                {error, _Reason} ->
                    exit(normal)
            end;
        {dist_data, Data} ->
            %% Data received from QUIC - buffer and deliver complete messages
            NewBuffer = <<Buffer/binary, Data/binary>>,
            case deliver_complete_messages(DHandle, NewBuffer) of
                {ok, RemainingBuffer} ->
                    input_handler_loop(
                        DHandle, Controller, ConnRef, ControlStream, RemainingBuffer
                    );
                {error, _Reason} ->
                    %% Error delivering to VM, connection is broken
                    exit(normal)
            end;
        {'EXIT', Controller, Reason} ->
            %% Controller died, exit
            exit(Reason);
        {quic, ConnRef, {stream_data, _StreamId, Data, _Fin}} ->
            %% Direct QUIC data (if we're receiving messages directly)
            NewBuffer = <<Buffer/binary, Data/binary>>,
            case deliver_complete_messages(DHandle, NewBuffer) of
                {ok, RemainingBuffer} ->
                    input_handler_loop(
                        DHandle, Controller, ConnRef, ControlStream, RemainingBuffer
                    );
                {error, _Reason} ->
                    exit(normal)
            end;
        {quic, ConnRef, {closed, _Reason}} ->
            exit(normal);
        Other ->
            logger:warning(
                #{what => input_handler_unexpected_msg, msg => Other},
                ?QUIC_LOG_META
            ),
            input_handler_loop(DHandle, Controller, ConnRef, ControlStream, Buffer)
    end.

%% @private
%% Deliver complete messages to the VM with batch limiting.
%% We use 4-byte length-prefixed framing: <<Length:32/big, Payload:Length/binary>>
%% The payload (WITHOUT length header) is passed to dist_ctrl_put_data.
%% Empty frames (Length=0) are tick signals - no payload to deliver.
%% Returns {ok, RemainingBuffer} or {error, Reason}
deliver_complete_messages(DHandle, Buffer) ->
    deliver_complete_messages(DHandle, Buffer, ?INPUT_HANDLER_BATCH_SIZE).

%% @private
%% Deliver complete messages with batch limit to prevent blocking.
%% After processing batch limit messages, yields back to receive loop
%% via continue_delivery message to allow processing incoming ticks.
deliver_complete_messages(_DHandle, Buffer, 0) ->
    %% Reached batch limit - yield to allow processing other messages (e.g., ticks)
    self() ! {continue_delivery, Buffer},
    {ok, <<>>};
deliver_complete_messages(DHandle, Buffer, Remaining) ->
    case Buffer of
        <<0:32/big-unsigned, Rest/binary>> ->
            %% Empty frame = tick signal - just continue (ticks don't count against batch limit)
            logger:debug(#{what => tick_frame_received}, ?QUIC_LOG_META),
            deliver_complete_messages(DHandle, Rest, Remaining);
        <<Length:32/big-unsigned, Rest/binary>> when byte_size(Rest) >= Length ->
            %% We have a complete message - extract payload only
            <<Payload:Length/binary, Tail/binary>> = Rest,
            logger:debug(
                #{
                    what => complete_message,
                    length => Length,
                    payload_first_bytes => binary:part(Payload, 0, min(16, byte_size(Payload)))
                },
                ?QUIC_LOG_META
            ),
            try
                %% Pass ONLY the payload to dist_ctrl_put_data (no length header)
                erlang:dist_ctrl_put_data(DHandle, Payload),
                %% Continue with remaining data, decrement batch counter
                deliver_complete_messages(DHandle, Tail, Remaining - 1)
            catch
                Class:Reason ->
                    logger:error(
                        #{
                            what => dist_ctrl_put_data_failed,
                            class => Class,
                            reason => Reason,
                            payload_size => Length
                        },
                        ?QUIC_LOG_META
                    ),
                    {error, {put_data_failed, Reason}}
            end;
        <<Length:32/big-unsigned, _Rest/binary>> ->
            %% Have header but incomplete payload - need more data
            logger:debug(
                #{
                    what => need_more_data,
                    expected_length => Length,
                    have_bytes => byte_size(_Rest)
                },
                ?QUIC_LOG_META
            ),
            {ok, Buffer};
        _ when byte_size(Buffer) < 4 ->
            %% Don't even have the header yet
            {ok, Buffer};
        _ ->
            %% This shouldn't happen - log and keep the buffer
            %% Check if this looks like unframed ETF data
            logger:warning(
                #{
                    what => unexpected_buffer_state,
                    buffer_size => byte_size(Buffer),
                    first_bytes => binary:part(Buffer, 0, min(20, byte_size(Buffer))),
                    looks_like_etf => (byte_size(Buffer) >= 1 andalso binary:first(Buffer) =:= 131)
                },
                ?QUIC_LOG_META
            ),
            {ok, Buffer}
    end.

%%====================================================================
%% Internal Functions - Receive
%%====================================================================

%% @private
%% Try to receive data from buffer.
%% When Length = 0, return all available data (like gen_tcp:recv/3).
try_recv(0, #state{recv_buffer = <<>>} = State) ->
    %% No data available, need more
    {need_more, State};
try_recv(0, #state{recv_buffer = Buffer} = State) ->
    %% Return all available data
    {ok, Buffer, State#state{recv_buffer = <<>>}};
try_recv(Length, #state{recv_buffer = Buffer} = State) when byte_size(Buffer) >= Length ->
    <<Data:Length/binary, Rest/binary>> = Buffer,
    {ok, Data, State#state{recv_buffer = Rest}};
try_recv(_Length, State) ->
    {need_more, State}.

%% @private
%% Handle data received on control stream.
%% During handshake: buffer data for f_recv (distribution handshake)
%% After handshake: control stream only receives tick frames (<<0:32>>)
%%                  which are ignored - NOT forwarded to input handler
handle_control_data(<<>>, _StateName, State) ->
    %% Empty data - signals liveness, nothing to process
    {keep_state, State};
handle_control_data(<<0:32/big-unsigned, Rest/binary>>, StateName, State) ->
    %% Tick frame on control stream - ignore payload, process rest
    handle_control_data(Rest, StateName, State);
handle_control_data(
    Data,
    StateName,
    #state{
        recv_buffer = Buffer,
        recv_waiters = Waiters,
        recv_cnt = RecvCnt,
        recv_oct = RecvOct
    } = State
) ->
    case StateName of
        connected ->
            %% In connected state, control stream should only have tick frames
            %% Any other data is unexpected - log and ignore to avoid corruption
            ?LOG_WARNING(
                #{
                    what => unexpected_control_data,
                    size => byte_size(Data),
                    first_bytes => binary:part(Data, 0, min(20, byte_size(Data)))
                },
                ?QUIC_LOG_META
            ),
            {keep_state, State};
        _ ->
            %% During handshake, buffer data for f_recv
            NewBuffer = <<Buffer/binary, Data/binary>>,
            State1 = State#state{
                recv_buffer = NewBuffer,
                recv_cnt = RecvCnt + 1,
                recv_oct = RecvOct + byte_size(Data),
                recv_waiters = []
            },
            {State2, Actions} = satisfy_waiters(Waiters, State1, []),
            {keep_state, State2, Actions}
    end.

%% @private
%% Handle data received on data streams.
%% In connected state, forward to input handler for VM delivery.
%% During handshake, buffer data (shouldn't happen for data streams).
handle_stream_data(
    _StreamId,
    Data,
    connected,
    #state{
        input_handler = InputHandler,
        recv_cnt = RecvCnt,
        recv_oct = RecvOct
    } = State
) when is_pid(InputHandler) ->
    %% Forward data stream content to input handler
    InputHandler ! {dist_data, Data},
    {keep_state, State#state{
        recv_cnt = RecvCnt + 1,
        recv_oct = RecvOct + byte_size(Data)
    }};
handle_stream_data(
    _StreamId,
    Data,
    _StateName,
    #state{
        pending_data_buffer = PendingBuffer,
        recv_cnt = RecvCnt,
        recv_oct = RecvOct
    } = State
) ->
    %% Data stream content arrived before we transitioned to connected state.
    %% This can happen due to race condition where peer sends distribution data
    %% before we've finished processing our handshake_complete message.
    %% Buffer it separately (NOT in recv_buffer which is for handshake) and
    %% forward to input handler once we transition to connected state.
    ?LOG_DEBUG(
        #{
            what => buffering_early_data_stream,
            size => byte_size(Data),
            pending_buffer_size => byte_size(PendingBuffer)
        },
        ?QUIC_LOG_META
    ),
    NewPendingBuffer = <<PendingBuffer/binary, Data/binary>>,
    {keep_state, State#state{
        pending_data_buffer = NewPendingBuffer,
        recv_cnt = RecvCnt + 1,
        recv_oct = RecvOct + byte_size(Data)
    }}.

%% @private
%% Try to satisfy waiting recv requests.
satisfy_waiters([], State, Actions) ->
    {State, lists:reverse(Actions)};
satisfy_waiters([{From, _Ref, Length} | Rest], State, Actions) ->
    case try_recv(Length, State) of
        {ok, Data, State1} ->
            %% dist_util expects data as a list (charlist), not binary
            DataList = binary_to_list(Data),
            satisfy_waiters(Rest, State1, [{reply, From, {ok, DataList}} | Actions]);
        {need_more, State1} ->
            %% Put waiter back
            {State1#state{recv_waiters = [{From, _Ref, Length} | Rest]}, lists:reverse(Actions)}
    end.
