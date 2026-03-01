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

    %% Receive buffer for control stream
    recv_buffer = <<>> :: binary(),
    recv_queue = queue:new() :: queue:queue(),
    recv_waiters = [] :: [{pid(), reference(), non_neg_integer()}],

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
    session_ticket :: term() | undefined
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
-spec recv(Controller :: pid(), Length :: non_neg_integer(),
           Timeout :: timeout()) ->
    {ok, binary()} | {error, term()}.
recv(Controller, Length, Timeout) ->
    gen_statem:call(Controller, {recv, Length}, Timeout).

%% @doc Send a tick message.
-spec tick(Controller :: pid()) -> ok.
tick(Controller) ->
    gen_statem:cast(Controller, tick).

%% @doc Get connection statistics.
-spec getstat(Controller :: pid()) ->
    {ok, RecvCnt :: non_neg_integer(), SendCnt :: non_neg_integer(),
     SendPend :: non_neg_integer()}.
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
            State = #state{
                conn_ref = ConnRef,
                conn_pid = ConnPid,
                role = client
            },
            {ok, init_state, State};
        error ->
            {stop, connection_not_found}
    end;

%% Initialize for server role
init({ConnPid, ConnRef, server}) ->
    State = #state{
        conn_ref = ConnRef,
        conn_pid = ConnPid,
        role = server
    },
    {ok, init_state, State}.

terminate(_Reason, _StateName, #state{conn_ref = ConnRef}) ->
    catch quic:close(ConnRef, normal),
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

%% Handle send during handshake
handshaking({call, From}, {send, Data}, #state{role = Role} = State) ->
    error_logger:info_msg("quic_dist_controller ~p: send(~p bytes) during handshake~n",
                          [Role, iolist_size(Data)]),
    case do_send_control(Data, State) of
        {ok, State1} ->
            error_logger:info_msg("quic_dist_controller ~p: send succeeded~n", [Role]),
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            error_logger:info_msg("quic_dist_controller ~p: send failed: ~p~n", [Role, Reason]),
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

%% Handle recv during handshake
handshaking({call, From}, {recv, Length}, #state{role = Role, recv_buffer = Buffer} = State) ->
    error_logger:info_msg("quic_dist_controller ~p: recv(~p) requested, buffer=~p bytes~n",
                          [Role, Length, byte_size(Buffer)]),
    case try_recv(Length, State) of
        {ok, Data, State1} ->
            %% dist_util expects data as a list (charlist), not binary
            DataList = binary_to_list(Data),
            error_logger:info_msg("quic_dist_controller ~p: recv returning ~p bytes~n",
                                  [Role, byte_size(Data)]),
            {keep_state, State1, [{reply, From, {ok, DataList}}]};
        {need_more, State1} ->
            %% Queue the waiter
            error_logger:info_msg("quic_dist_controller ~p: recv needs more data, queuing waiter~n", [Role]),
            Ref = make_ref(),
            Waiters = [{From, Ref, Length} | State1#state.recv_waiters],
            {keep_state, State1#state{recv_waiters = Waiters}};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

%% Handshake complete notification with DHandle
handshaking(info, {handshake_complete, Node, DHandle}, State) ->
    error_logger:info_msg("quic_dist_controller: handshake complete, Node=~p, DHandle=~p~n", [Node, DHandle]),

    %% Set up distribution control machinery
    %% This is required for process-based distribution to work properly

    %% Spawn input handler to receive QUIC data and deliver to VM
    Self = self(),
    ConnRef = State#state.conn_ref,
    ControlStream = State#state.control_stream,
    InputHandler = spawn_link(
        fun() ->
            input_handler_loop(DHandle, Self, ConnRef, ControlStream)
        end),

    %% Register input handler with VM
    ok = erlang:dist_ctrl_input_handler(DHandle, InputHandler),

    %% Request notification when outgoing data is available
    erlang:dist_ctrl_get_data_notification(DHandle),

    State1 = State#state{
        node = Node,
        dhandle = DHandle,
        input_handler = InputHandler
    },
    {next_state, connected, State1};

%% Legacy handshake complete notification (for backward compatibility)
handshaking(info, {handshake_complete, Node}, State) ->
    error_logger:warning_msg("quic_dist_controller: handshake_complete without DHandle~n"),
    State1 = State#state{node = Node},
    {next_state, connected, State1};

handshaking(EventType, Event, State) ->
    handle_common_event(EventType, Event, handshaking, State).

%%====================================================================
%% State: connected
%%====================================================================

connected(enter, _OldState, _State) ->
    %% No tick timer needed - VM handles tick scheduling via dist_data
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
            {keep_state, State1#state{recv_waiters = Waiters}};
        {error, Reason} ->
            {keep_state, State, [{reply, From, {error, Reason}}]}
    end;

%% Handle tick (from mf_tick callback)
connected(cast, tick, #state{dhandle = DHandle} = State) when DHandle /= undefined ->
    %% Tick is handled via dist_data - just send any pending data
    send_dist_data(State),
    {keep_state, State};

connected(cast, tick, State) ->
    %% No DHandle, use old tick method
    do_send_tick(State),
    {keep_state, State};

%% Handle dist_data notification from VM
%% This means the VM has data ready for us to send
connected(info, dist_data, #state{dhandle = DHandle} = State) when DHandle /= undefined ->
    error_logger:info_msg("quic_dist_controller: dist_data received~n"),
    send_dist_data(State),
    %% Re-register for next notification
    erlang:dist_ctrl_get_data_notification(DHandle),
    {keep_state, State};

connected(EventType, Event, State) ->
    handle_common_event(EventType, Event, connected, State).

%%====================================================================
%% Common Event Handling
%%====================================================================

handle_common_event({call, From}, getstat, _StateName, State) ->
    #state{recv_cnt = RecvCnt, send_cnt = SendCnt} = State,
    SendPend = queue:len(State#state.send_queue),
    {keep_state, State, [{reply, From, {ok, RecvCnt, SendCnt, SendPend}}]};

handle_common_event({call, From}, {get_address, Node}, _StateName,
                    #state{conn_ref = ConnRef} = State) ->
    Address = case quic:peername(ConnRef) of
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
    Reply = case Node of
        undefined -> undefined;
        _ -> {ok, Node}
    end,
    {keep_state, State, [{reply, From, Reply}]};

handle_common_event({call, From}, getll, _StateName, State) ->
    {keep_state, State, [{reply, From, {ok, self()}}]};

handle_common_event({call, From}, {pre_nodeup, SetupPid}, _StateName,
                    #state{kernel = Kernel, node = Node} = State) ->
    %% Send dist_ctrlr message to kernel to register this controller
    %% This is required before mark_nodeup can succeed
    case {Kernel, Node} of
        {undefined, _} ->
            error_logger:warning_msg("quic_dist_controller: pre_nodeup called but kernel is undefined~n"),
            {keep_state, State, [{reply, From, ok}]};
        {_, undefined} ->
            error_logger:warning_msg("quic_dist_controller: pre_nodeup called but node is undefined~n"),
            {keep_state, State, [{reply, From, ok}]};
        {K, N} when is_pid(K), is_atom(N) ->
            error_logger:info_msg("quic_dist_controller: sending dist_ctrlr to ~p for node ~p~n", [K, N]),
            K ! {dist_ctrlr, self(), N, SetupPid},
            {keep_state, State, [{reply, From, ok}]}
    end;

%% Handle incoming QUIC messages
handle_common_event(info, {quic, ConnRef, {stream_data, StreamId, Data, _Fin}},
                    StateName, #state{conn_ref = ConnRef,
                                      control_stream = CtrlStream,
                                      role = Role} = State) ->
    error_logger:info_msg("quic_dist_controller ~p(~p): stream_data on stream ~p, control=~p, ~p bytes~n",
                          [Role, StateName, StreamId, CtrlStream, byte_size(Data)]),
    case StreamId of
        CtrlStream ->
            %% Data on control stream
            handle_control_data(Data, StateName, State);
        _ ->
            %% Data on data stream
            handle_stream_data(StreamId, Data, StateName, State)
    end;

handle_common_event(info, {quic, ConnRef, {session_ticket, Ticket}},
                    _StateName, #state{conn_ref = ConnRef} = State) ->
    %% Store session ticket for 0-RTT
    {keep_state, State#state{session_ticket = Ticket}};

handle_common_event(info, {quic, ConnRef, {connected, _Info}},
                    _StateName, #state{conn_ref = ConnRef} = State) ->
    %% Connection fully established - we may receive this after transitioning
    %% to handshaking state, just acknowledge and continue
    {keep_state, State};

handle_common_event(info, {quic, ConnRef, {stream_opened, _StreamId}},
                    _StateName, #state{conn_ref = ConnRef} = State) ->
    %% New stream opened by peer - for distribution, we primarily use stream 0
    {keep_state, State};

handle_common_event(info, {quic, ConnRef, {closed, Reason}},
                    _StateName, #state{conn_ref = ConnRef} = State) ->
    %% Connection closed
    {stop, {connection_closed, Reason}, State};

handle_common_event(info, {quic, ConnRef, {transport_error, Code, Reason}},
                    _StateName, #state{conn_ref = ConnRef} = State) ->
    {stop, {transport_error, Code, Reason}, State};

handle_common_event(info, {quic, _OtherRef, {stream_data, StreamId, Data, _Fin}},
                    StateName, #state{conn_ref = ConnRef, role = Role} = State) ->
    %% Stream data with non-matching ConnRef (should not happen)
    error_logger:warning_msg("quic_dist_controller ~p(~p): stream_data on ~p (~p bytes) but ConnRef mismatch (expected ~p)~n",
                              [Role, StateName, StreamId, byte_size(Data), ConnRef]),
    {keep_state, State};

handle_common_event(_EventType, _Event, _StateName, State) ->
    {keep_state, State}.

%%====================================================================
%% Internal Functions - Streams
%%====================================================================

%% @private
%% Open the control stream.
open_control_stream(#state{conn_ref = ConnRef, role = Role} = State) ->
    case Role of
        client ->
            %% Client opens stream 0
            case quic:open_stream(ConnRef) of
                {ok, StreamId} ->
                    {ok, StreamId, State};
                Error ->
                    Error
            end;
        server ->
            %% Server waits for stream from client
            %% For now, we use a fixed stream ID
            {ok, 0, State}
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
            error_logger:warning_msg("quic_dist_controller: Failed to open data stream: ~p~n",
                                     [Reason]),
            {ok, State}
    end.

%% @private
set_stream_priority(#state{conn_ref = ConnRef}, StreamId, Urgency) ->
    quic:set_stream_priority(ConnRef, StreamId, Urgency, false).

%%====================================================================
%% Internal Functions - Send
%%====================================================================

%% @private
%% Send data on control stream (handshake messages).
%% Note: No framing needed - dist_util handles its own protocol framing.
do_send_control(Data, #state{conn_ref = ConnRef,
                              control_stream = StreamId,
                              send_cnt = SendCnt,
                              send_oct = SendOct} = State) ->
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
do_send_data(Data, #state{conn_ref = ConnRef,
                          data_streams = Streams,
                          data_stream_idx = Idx,
                          send_cnt = SendCnt,
                          send_oct = SendOct} = State) when Streams =/= [] ->
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
%% Send a tick message on control stream (legacy, without dist_ctrl).
do_send_tick(#state{conn_ref = ConnRef, control_stream = StreamId}) ->
    case StreamId of
        undefined ->
            ok;
        _ ->
            error_logger:info_msg("quic_dist_controller: sending legacy tick~n"),
            case quic:send_data(ConnRef, StreamId, <<>>, false) of
                ok -> ok;
                {error, _Reason} -> ok
            end
    end.

%% @private
%% Send distribution data from VM via QUIC.
%% Called when dist_data notification is received.
send_dist_data(#state{dhandle = DHandle, conn_ref = ConnRef, control_stream = StreamId}) ->
    send_dist_data_loop(DHandle, ConnRef, StreamId).

send_dist_data_loop(DHandle, ConnRef, StreamId) ->
    case erlang:dist_ctrl_get_data(DHandle) of
        none ->
            %% No more data to send
            ok;
        Data ->
            %% Send data over QUIC control stream
            error_logger:info_msg("quic_dist_controller: sending dist data ~p bytes~n", [iolist_size(Data)]),
            case quic:send_data(ConnRef, StreamId, iolist_to_binary(Data), false) of
                ok ->
                    %% Try to get more data
                    send_dist_data_loop(DHandle, ConnRef, StreamId);
                {error, Reason} ->
                    error_logger:error_msg("quic_dist_controller: send failed: ~p~n", [Reason]),
                    ok
            end
    end.

%%====================================================================
%% Input Handler - receives QUIC data and delivers to VM
%%====================================================================

%% @private
%% Input handler loop - receives QUIC data from controller and delivers to VM.
%% This runs in a separate process registered with erlang:dist_ctrl_input_handler.
input_handler_loop(DHandle, Controller, ConnRef, _ControlStream) ->
    receive
        {dist_data, Data} ->
            %% Data received from QUIC - deliver to VM
            error_logger:info_msg("input_handler: putting ~p bytes to VM~n", [byte_size(Data)]),
            try
                erlang:dist_ctrl_put_data(DHandle, Data)
            catch
                Class:Reason ->
                    error_logger:error_msg("input_handler: dist_ctrl_put_data failed: ~p:~p~n", [Class, Reason]),
                    exit(normal)
            end,
            input_handler_loop(DHandle, Controller, ConnRef, _ControlStream);

        {'EXIT', Controller, Reason} ->
            %% Controller died, exit
            exit(Reason);

        {quic, ConnRef, {stream_data, _StreamId, Data, _Fin}} ->
            %% Direct QUIC data (if we're receiving messages directly)
            try
                erlang:dist_ctrl_put_data(DHandle, Data)
            catch
                _:_ ->
                    exit(normal)
            end,
            input_handler_loop(DHandle, Controller, ConnRef, _ControlStream);

        {quic, ConnRef, {closed, _Reason}} ->
            exit(normal);

        Other ->
            error_logger:warning_msg("input_handler: unexpected message ~p~n", [Other]),
            input_handler_loop(DHandle, Controller, ConnRef, _ControlStream)
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
handle_control_data(Data, StateName, #state{recv_buffer = Buffer,
                                              recv_waiters = Waiters,
                                              recv_cnt = RecvCnt,
                                              recv_oct = RecvOct,
                                              role = Role,
                                              input_handler = InputHandler} = State) ->
    %% Debug: log received data
    error_logger:info_msg("quic_dist_controller ~p(~p): received ~p bytes on control stream, waiters=~p~n",
                          [Role, StateName, byte_size(Data), length(Waiters)]),

    %% After handshake, forward data to input handler
    case {StateName, InputHandler} of
        {connected, Pid} when is_pid(Pid) ->
            %% Forward to input handler which calls dist_ctrl_put_data
            Pid ! {dist_data, Data},
            State1 = State#state{
                recv_cnt = RecvCnt + 1,
                recv_oct = RecvOct + byte_size(Data)
            },
            {keep_state, State1};
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
handle_stream_data(_StreamId, Data, _StateName,
                   #state{recv_buffer = Buffer,
                          recv_cnt = RecvCnt,
                          recv_oct = RecvOct,
                          recv_waiters = Waiters} = State) ->
    %% Add data to buffer
    NewBuffer = <<Buffer/binary, Data/binary>>,
    State1 = State#state{
        recv_buffer = NewBuffer,
        recv_cnt = RecvCnt + 1,
        recv_oct = RecvOct + byte_size(Data)
    },
    %% Try to satisfy any waiting recv requests
    case Waiters of
        [] ->
            {keep_state, State1};
        _ ->
            {State2, Actions} = satisfy_waiters(Waiters, State1#state{recv_waiters = []}, []),
            {keep_state, State2, Actions}
    end.

%% @private
%% Try to satisfy waiting recv requests.
satisfy_waiters([], State, Actions) ->
    {State, lists:reverse(Actions)};
satisfy_waiters([{From, _Ref, Length} | Rest], #state{recv_buffer = Buffer} = State, Actions) ->
    error_logger:info_msg("satisfy_waiters: trying Length=~p, buffer=~p bytes~n",
                          [Length, byte_size(Buffer)]),
    case try_recv(Length, State) of
        {ok, Data, State1} ->
            %% dist_util expects data as a list (charlist), not binary
            DataList = binary_to_list(Data),
            error_logger:info_msg("satisfy_waiters: satisfied with ~p bytes~n", [byte_size(Data)]),
            satisfy_waiters(Rest, State1, [{reply, From, {ok, DataList}} | Actions]);
        {need_more, State1} ->
            %% Put waiter back
            error_logger:info_msg("satisfy_waiters: need more data~n", []),
            {State1#state{recv_waiters = [{From, _Ref, Length} | Rest]}, lists:reverse(Actions)}
    end.
