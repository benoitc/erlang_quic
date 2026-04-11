%%% -*- erlang -*-
%%%
%%% HTTP/3 connection state machine (RFC 9114)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc HTTP/3 connection management.
%%%
%%% This module implements the HTTP/3 connection layer on top of QUIC.
%%% It manages critical unidirectional streams (control, QPACK encoder/decoder),
%%% request/response streams, and the HTTP/3 protocol state machine.
%%% @end

-module(quic_h3_connection).

-behaviour(gen_statem).

%% API
-export([
    start_link/3,
    start_link/4,
    request/2,
    request/3,
    send_response/4,
    send_data/3,
    send_data/4,
    send_trailers/3,
    cancel_stream/2,
    cancel_stream/3,
    goaway/1,
    close/1,
    get_settings/1,
    get_peer_settings/1
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
    awaiting_quic/3,
    h3_connecting/3,
    connected/3,
    goaway_sent/3,
    goaway_received/3,
    closing/3
]).

-include("quic.hrl").
-include("quic_h3.hrl").

%% Test exports - only available when compiled with TEST defined
-ifdef(TEST).
-export([
    handle_stream_closed/2,
    handle_control_frame/2,
    handle_request_frame/5,
    is_critical_stream/2,
    partition_blocked_streams/2
]).
-endif.

%%====================================================================
%% Types
%%====================================================================

-type role() :: client | server.
-type stream_id() :: non_neg_integer().
-type error_code() :: non_neg_integer().

-record(state, {
    %% Underlying QUIC connection
    quic_conn :: pid(),
    quic_ref :: reference(),

    %% Role: client or server
    role :: role(),

    %% Owner process (receives events)
    owner :: pid(),
    owner_monitor :: reference(),

    %% Critical unidirectional streams (local)
    local_control_stream :: stream_id() | undefined,
    local_encoder_stream :: stream_id() | undefined,
    local_decoder_stream :: stream_id() | undefined,

    %% Critical unidirectional streams (peer)
    peer_control_stream :: stream_id() | undefined,
    peer_encoder_stream :: stream_id() | undefined,
    peer_decoder_stream :: stream_id() | undefined,

    %% QPACK state
    qpack_encoder :: quic_qpack:state(),
    qpack_decoder :: quic_qpack:state(),

    %% Settings
    local_settings :: map(),
    peer_settings :: map() | undefined,
    settings_sent = false :: boolean(),
    settings_received = false :: boolean(),

    %% GOAWAY state
    goaway_id :: stream_id() | undefined,
    last_stream_id = 0 :: stream_id(),

    %% Request streams: StreamId -> #h3_stream{}
    streams = #{} :: #{stream_id() => #h3_stream{}},

    %% Next stream ID for client-initiated requests
    next_stream_id :: stream_id(),

    %% Pending data buffers for partial frame decoding
    stream_buffers = #{} :: #{stream_id() => binary()},

    %% Pending uni stream type detection
    uni_stream_buffers = #{} :: #{stream_id() => binary()},

    %% QPACK instruction buffers for partial instructions (RFC 9204 Section 4.5)
    encoder_buffer = <<>> :: binary(),
    decoder_buffer = <<>> :: binary(),

    %% Blocked streams waiting for encoder instructions (RFC 9204 Section 2.2.2)
    %% Maps StreamId -> {RequiredInsertCount, HeaderBlock, Fin}
    blocked_streams = #{} :: #{stream_id() => {non_neg_integer(), binary(), boolean()}}
}).

%%====================================================================
%% API
%%====================================================================

%% @doc Start an HTTP/3 connection as a client.
-spec start_link(pid(), binary(), pos_integer()) ->
    {ok, pid()} | {error, term()}.
start_link(QuicConn, Host, Port) ->
    start_link(QuicConn, Host, Port, #{}).

%% @doc Start an HTTP/3 connection with options.
-spec start_link(pid(), binary(), pos_integer(), map()) ->
    {ok, pid()} | {error, term()}.
start_link(QuicConn, Host, Port, Opts) ->
    gen_statem:start_link(?MODULE, {client, QuicConn, Host, Port, Opts, self()}, []).

%% @doc Send a request (client only).
%% Returns the stream ID for tracking the response.
-spec request(pid(), [{binary(), binary()}]) ->
    {ok, stream_id()} | {error, term()}.
request(Conn, Headers) ->
    request(Conn, Headers, #{}).

-spec request(pid(), [{binary(), binary()}], map()) ->
    {ok, stream_id()} | {error, term()}.
request(Conn, Headers, Opts) ->
    gen_statem:call(Conn, {request, Headers, Opts}).

%% @doc Send a response (server only).
-spec send_response(pid(), stream_id(), pos_integer(), [{binary(), binary()}]) ->
    ok | {error, term()}.
send_response(Conn, StreamId, Status, Headers) ->
    gen_statem:call(Conn, {send_response, StreamId, Status, Headers}).

%% @doc Send body data on a stream.
-spec send_data(pid(), stream_id(), binary()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data) ->
    send_data(Conn, StreamId, Data, false).

-spec send_data(pid(), stream_id(), binary(), boolean()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data, Fin) ->
    gen_statem:call(Conn, {send_data, StreamId, Data, Fin}).

%% @doc Send trailers on a stream.
-spec send_trailers(pid(), stream_id(), [{binary(), binary()}]) ->
    ok | {error, term()}.
send_trailers(Conn, StreamId, Trailers) ->
    gen_statem:call(Conn, {send_trailers, StreamId, Trailers}).

%% @doc Cancel a stream.
-spec cancel_stream(pid(), stream_id()) -> ok.
cancel_stream(Conn, StreamId) ->
    cancel_stream(Conn, StreamId, ?H3_REQUEST_CANCELLED).

-spec cancel_stream(pid(), stream_id(), error_code()) -> ok.
cancel_stream(Conn, StreamId, ErrorCode) ->
    gen_statem:cast(Conn, {cancel_stream, StreamId, ErrorCode}).

%% @doc Initiate graceful shutdown.
-spec goaway(pid()) -> ok.
goaway(Conn) ->
    gen_statem:cast(Conn, goaway).

%% @doc Close the connection.
-spec close(pid()) -> ok.
close(Conn) ->
    gen_statem:cast(Conn, close).

%% @doc Get local settings.
-spec get_settings(pid()) -> map().
get_settings(Conn) ->
    gen_statem:call(Conn, get_settings).

%% @doc Get peer settings.
-spec get_peer_settings(pid()) -> map() | undefined.
get_peer_settings(Conn) ->
    gen_statem:call(Conn, get_peer_settings).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() ->
    [state_functions, state_enter].

init({client, QuicConn, _Host, _Port, Opts, Owner}) ->
    process_flag(trap_exit, true),
    MonRef = monitor(process, Owner),
    QuicRef = monitor(process, QuicConn),

    LocalSettings = maps:merge(quic_h3_frame:default_settings(), maps:get(settings, Opts, #{})),
    MaxTableCapacity = maps:get(qpack_max_table_capacity, LocalSettings, 0),

    State = #state{
        quic_conn = QuicConn,
        quic_ref = QuicRef,
        role = client,
        owner = Owner,
        owner_monitor = MonRef,
        local_settings = LocalSettings,
        qpack_encoder = quic_qpack:new(#{max_dynamic_size => MaxTableCapacity}),
        qpack_decoder = quic_qpack:new(#{max_dynamic_size => MaxTableCapacity}),
        % Client uses even stream IDs (0, 4, 8, ...)
        next_stream_id = 0
    },

    %% Start in awaiting_quic - wait for QUIC connected notification
    %% H3 streams should not be opened until QUIC connection is established
    {ok, awaiting_quic, State};
init({server, QuicConn, Opts, Owner}) ->
    process_flag(trap_exit, true),
    MonRef = monitor(process, Owner),
    QuicRef = monitor(process, QuicConn),

    LocalSettings = maps:merge(quic_h3_frame:default_settings(), maps:get(settings, Opts, #{})),
    MaxTableCapacity = maps:get(qpack_max_table_capacity, LocalSettings, 0),
    Handler = maps:get(handler, Opts, undefined),

    State = #state{
        quic_conn = QuicConn,
        quic_ref = QuicRef,
        role = server,
        owner = Owner,
        owner_monitor = MonRef,
        local_settings = LocalSettings,
        qpack_encoder = quic_qpack:new(#{max_dynamic_size => MaxTableCapacity}),
        qpack_decoder = quic_qpack:new(#{max_dynamic_size => MaxTableCapacity}),
        % Server uses odd stream IDs (1, 5, 9, ...)
        next_stream_id = 1
    },

    %% Store handler in process dictionary for server
    case Handler of
        undefined -> ok;
        _ -> put(h3_handler, Handler)
    end,

    %% Start in awaiting_quic - wait for QUIC connected notification
    %% H3 streams should not be opened until QUIC connection is established
    {ok, awaiting_quic, State}.

terminate(_Reason, _StateName, #state{quic_conn = QuicConn}) ->
    catch quic:close(QuicConn),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%====================================================================
%% State: awaiting_quic
%% Wait for QUIC connection to be established before opening H3 streams
%%====================================================================

awaiting_quic(enter, _OldState, _State) ->
    %% Wait for QUIC connected notification (ownership transferred by quic_h3:connect)
    keep_state_and_data;
%% Match on quic_conn pid, not quic_ref (which is a monitor reference)
awaiting_quic(info, {quic, QuicConn, {connected, _Info}}, #state{quic_conn = QuicConn} = State) ->
    %% QUIC is ready - transition to h3_connecting to open H3 streams
    {next_state, h3_connecting, State};
%% Postpone stream data received before we're ready
awaiting_quic(info, {quic, QuicConn, {stream_data, _, _, _}}, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [postpone]};
awaiting_quic(info, {quic, QuicConn, {new_stream, _, _}}, #state{quic_conn = QuicConn}) ->
    {keep_state_and_data, [postpone]};
awaiting_quic({call, From}, {request, _Headers, _Opts}, _State) ->
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};
awaiting_quic({call, From}, get_settings, #state{local_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
awaiting_quic({call, From}, get_peer_settings, #state{peer_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
awaiting_quic(cast, close, State) ->
    {next_state, closing, State};
awaiting_quic(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
awaiting_quic(info, {'DOWN', Ref, process, _, _}, #state{quic_ref = Ref} = State) ->
    {stop, quic_closed, State};
awaiting_quic(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: h3_connecting
%% Open critical H3 streams and exchange SETTINGS
%%====================================================================

h3_connecting(enter, _OldState, State) ->
    %% Open critical streams and send SETTINGS
    case open_critical_streams(State) of
        {ok, State1} ->
            case send_settings(State1) of
                {ok, State2} ->
                    {keep_state, State2};
                {error, Reason} ->
                    {stop, {error, Reason}}
            end;
        {error, Reason} ->
            {stop, {error, Reason}}
    end;
h3_connecting(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            maybe_transition_connected(State1);
        {transition, goaway_received, State1} ->
            %% GOAWAY received during connecting - transition to goaway_received
            {next_state, goaway_received, State1};
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
h3_connecting(
    info,
    {quic, QuicConn, {new_stream, StreamId, Type}},
    #state{quic_conn = QuicConn} = State
) ->
    State1 = handle_new_stream(StreamId, Type, State),
    {keep_state, State1};
h3_connecting(
    info,
    {quic, QuicConn, {stream_closed, StreamId, _ErrorCode}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_closed(StreamId, State) of
        {ok, State1} ->
            {keep_state, State1};
        {error, Reason} ->
            handle_connection_error(Reason, State)
    end;
h3_connecting({call, From}, {request, _Headers, _Opts}, _State) ->
    %% Can't send requests until connected
    {keep_state_and_data, [{reply, From, {error, not_connected}}]};
h3_connecting({call, From}, get_settings, #state{local_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
h3_connecting({call, From}, get_peer_settings, #state{peer_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
h3_connecting(cast, close, State) ->
    {next_state, closing, State};
h3_connecting(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
h3_connecting(info, {'DOWN', Ref, process, _, _}, #state{quic_ref = Ref} = State) ->
    {stop, quic_closed, State};
h3_connecting(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: connected
%%====================================================================

connected(enter, _OldState, #state{owner = Owner} = State) ->
    Owner ! {quic_h3, self(), connected},
    {keep_state, State};
connected(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1};
        {transition, goaway_received, State1} ->
            %% GOAWAY received - transition to goaway_received
            {next_state, goaway_received, State1};
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
connected(
    info,
    {quic, QuicConn, {new_stream, StreamId, Type}},
    #state{quic_conn = QuicConn} = State
) ->
    State1 = handle_new_stream(StreamId, Type, State),
    {keep_state, State1};
connected(
    info,
    {quic, QuicConn, {stream_closed, StreamId, ErrorCode}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_closed(StreamId, State) of
        {ok, State1} ->
            notify_stream_reset(StreamId, ErrorCode, State1),
            {keep_state, State1};
        {error, Reason} ->
            handle_connection_error(Reason, State)
    end;
connected({call, From}, {request, Headers, Opts}, #state{role = client} = State) ->
    case send_request(Headers, Opts, State) of
        {ok, StreamId, State1} ->
            {keep_state, State1, [{reply, From, {ok, StreamId}}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {request, _Headers, _Opts}, #state{role = server}) ->
    {keep_state_and_data, [{reply, From, {error, server_cannot_request}}]};
connected({call, From}, {send_response, StreamId, Status, Headers}, State) ->
    case do_send_response(StreamId, Status, Headers, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, {send_trailers, StreamId, Trailers}, State) ->
    case do_send_trailers(StreamId, Trailers, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
connected({call, From}, get_settings, #state{local_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
connected({call, From}, get_peer_settings, #state{peer_settings = Settings}) ->
    {keep_state_and_data, [{reply, From, Settings}]};
connected(cast, {cancel_stream, StreamId, ErrorCode}, State) ->
    State1 = do_cancel_stream(StreamId, ErrorCode, State),
    {keep_state, State1};
connected(cast, goaway, State) ->
    case send_goaway(State) of
        {ok, State1} ->
            {next_state, goaway_sent, State1};
        {error, _Reason} ->
            {next_state, closing, State}
    end;
connected(cast, close, State) ->
    {next_state, closing, State};
connected(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
connected(info, {'DOWN', Ref, process, _, _}, #state{quic_ref = Ref} = State) ->
    {stop, quic_closed, State};
connected(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: goaway_sent
%%====================================================================

goaway_sent(enter, _OldState, #state{owner = Owner, goaway_id = GoawayId}) ->
    Owner ! {quic_h3, self(), {goaway_sent, GoawayId}},
    keep_state_and_data;
goaway_sent(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    %% Continue processing existing streams
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            maybe_close_if_drained(State1);
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
goaway_sent({call, From}, {request, _Headers, _Opts}, _State) ->
    {keep_state_and_data, [{reply, From, {error, goaway_sent}}]};
goaway_sent({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    %% Allow completing existing streams
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
goaway_sent(cast, close, State) ->
    {next_state, closing, State};
goaway_sent(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
goaway_sent(info, {'DOWN', Ref, process, _, _}, #state{quic_ref = Ref} = State) ->
    {stop, quic_closed, State};
goaway_sent(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: goaway_received
%%====================================================================

goaway_received(enter, _OldState, #state{owner = Owner, goaway_id = GoawayId}) ->
    Owner ! {quic_h3, self(), {goaway, GoawayId}},
    keep_state_and_data;
goaway_received(
    info,
    {quic, QuicConn, {stream_data, StreamId, Data, Fin}},
    #state{quic_conn = QuicConn} = State
) ->
    case handle_stream_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            maybe_close_if_drained(State1);
        {error, Reason, State1} ->
            handle_connection_error(Reason, State1)
    end;
goaway_received({call, From}, {request, _Headers, _Opts}, _State) ->
    {keep_state_and_data, [{reply, From, {error, goaway_received}}]};
goaway_received({call, From}, {send_data, StreamId, Data, Fin}, State) ->
    case do_send_data(StreamId, Data, Fin, State) of
        {ok, State1} ->
            {keep_state, State1, [{reply, From, ok}]};
        {error, Reason} ->
            {keep_state_and_data, [{reply, From, {error, Reason}}]}
    end;
goaway_received(cast, close, State) ->
    {next_state, closing, State};
goaway_received(info, {'DOWN', Ref, process, _, _}, #state{owner_monitor = Ref} = State) ->
    {next_state, closing, State};
goaway_received(info, {'DOWN', Ref, process, _, _}, #state{quic_ref = Ref} = State) ->
    {stop, quic_closed, State};
goaway_received(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% State: closing
%%====================================================================

closing(enter, _OldState, #state{quic_conn = QuicConn, owner = Owner}) ->
    catch quic:close(QuicConn),
    Owner ! {quic_h3, self(), closed},
    {stop, normal};
closing(_EventType, _Event, _State) ->
    keep_state_and_data.

%%====================================================================
%% Internal: Critical Streams
%%====================================================================

open_critical_streams(#state{quic_conn = QuicConn} = State) ->
    %% Open control stream
    case quic:open_unidirectional_stream(QuicConn) of
        {ok, ControlStreamId} ->
            %% Send stream type
            TypeData = quic_h3_frame:encode_stream_type(control),
            ok = quic:send_data(QuicConn, ControlStreamId, TypeData, false),

            %% Open QPACK encoder stream
            case quic:open_unidirectional_stream(QuicConn) of
                {ok, EncoderStreamId} ->
                    EncTypeData = quic_h3_frame:encode_stream_type(qpack_encoder),
                    ok = quic:send_data(QuicConn, EncoderStreamId, EncTypeData, false),

                    %% Open QPACK decoder stream
                    case quic:open_unidirectional_stream(QuicConn) of
                        {ok, DecoderStreamId} ->
                            DecTypeData = quic_h3_frame:encode_stream_type(qpack_decoder),
                            ok = quic:send_data(QuicConn, DecoderStreamId, DecTypeData, false),

                            {ok, State#state{
                                local_control_stream = ControlStreamId,
                                local_encoder_stream = EncoderStreamId,
                                local_decoder_stream = DecoderStreamId
                            }};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

send_settings(
    #state{
        quic_conn = QuicConn,
        local_control_stream = ControlStream,
        local_settings = Settings
    } = State
) ->
    SettingsFrame = quic_h3_frame:encode_settings(Settings),
    case quic:send_data(QuicConn, ControlStream, SettingsFrame, false) of
        ok ->
            {ok, State#state{settings_sent = true}};
        {error, Reason} ->
            {error, Reason}
    end.

%%====================================================================
%% Internal: Stream Handling
%%====================================================================

handle_new_stream(StreamId, unidirectional, State) ->
    %% Unidirectional stream - need to read type first
    State#state{uni_stream_buffers = maps:put(StreamId, <<>>, State#state.uni_stream_buffers)};
handle_new_stream(StreamId, bidirectional, #state{streams = Streams, role = Role} = State) ->
    %% Bidirectional stream is a request stream
    Stream = #h3_stream{
        id = StreamId,
        type = request,
        state = open
    },
    %% For server, this is an incoming request
    %% For client, we opened it ourselves
    NewState = State#state{streams = Streams#{StreamId => Stream}},
    case Role of
        server ->
            NewState#state{last_stream_id = max(StreamId, State#state.last_stream_id)};
        client ->
            NewState
    end.

handle_stream_data(StreamId, Data, Fin, State) ->
    case classify_stream(StreamId, State) of
        {uni, pending} ->
            handle_uni_stream_type(StreamId, Data, State);
        {uni, control} ->
            %% Control stream may trigger state transition (GOAWAY)
            handle_control_stream_data(StreamId, Data, State);
        {uni, qpack_encoder} ->
            handle_encoder_stream_data(Data, State);
        {uni, qpack_decoder} ->
            handle_decoder_stream_data(Data, State);
        {bidi, request} ->
            handle_request_stream_data(StreamId, Data, Fin, State);
        unknown ->
            %% New unidirectional stream
            handle_uni_stream_type(StreamId, Data, State)
    end.

classify_stream(StreamId, #state{peer_control_stream = StreamId}) ->
    {uni, control};
classify_stream(StreamId, #state{peer_encoder_stream = StreamId}) ->
    {uni, qpack_encoder};
classify_stream(StreamId, #state{peer_decoder_stream = StreamId}) ->
    {uni, qpack_decoder};
classify_stream(StreamId, #state{uni_stream_buffers = Buffers}) ->
    case maps:is_key(StreamId, Buffers) of
        true ->
            {uni, pending};
        false ->
            %% Check if it's a bidirectional stream (bit 1 = 0 for bidi)
            case StreamId band 2 of
                0 -> {bidi, request};
                2 -> unknown
            end
    end.

handle_uni_stream_type(StreamId, Data, #state{uni_stream_buffers = Buffers} = State) ->
    Buffer = maps:get(StreamId, Buffers, <<>>),
    Combined = <<Buffer/binary, Data/binary>>,
    case quic_h3_frame:decode_stream_type(Combined) of
        {ok, Type, Rest} ->
            State1 = State#state{uni_stream_buffers = maps:remove(StreamId, Buffers)},
            case assign_uni_stream(StreamId, Type, State1) of
                {ok, State2} ->
                    %% Process remaining data if any
                    case Rest of
                        <<>> -> {ok, State2};
                        _ -> handle_stream_data(StreamId, Rest, false, State2)
                    end;
                {error, Reason} ->
                    {error, Reason, State1}
            end;
        {more, _} ->
            {ok, State#state{uni_stream_buffers = Buffers#{StreamId => Combined}}}
    end.

assign_uni_stream(StreamId, control, #state{peer_control_stream = undefined} = State) ->
    {ok, State#state{peer_control_stream = StreamId}};
assign_uni_stream(_StreamId, control, _State) ->
    %% Duplicate control stream
    {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"duplicate control stream">>}};
assign_uni_stream(StreamId, qpack_encoder, #state{peer_encoder_stream = undefined} = State) ->
    {ok, State#state{peer_encoder_stream = StreamId}};
assign_uni_stream(_StreamId, qpack_encoder, _State) ->
    {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"duplicate encoder stream">>}};
assign_uni_stream(StreamId, qpack_decoder, #state{peer_decoder_stream = undefined} = State) ->
    {ok, State#state{peer_decoder_stream = StreamId}};
assign_uni_stream(_StreamId, qpack_decoder, _State) ->
    {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"duplicate decoder stream">>}};
assign_uni_stream(_StreamId, push, #state{role = server}) ->
    %% Server can't receive push streams
    {error, {connection_error, ?H3_STREAM_CREATION_ERROR, <<"server received push stream">>}};
assign_uni_stream(_StreamId, push, #state{role = client} = State) ->
    %% We don't support push yet - ignore
    {ok, State};
assign_uni_stream(_StreamId, {unknown, _Type}, State) ->
    %% Unknown stream types are ignored per RFC 9114
    {ok, State}.

handle_control_stream_data(StreamId, Data, #state{stream_buffers = Buffers} = State) ->
    Buffer = maps:get(StreamId, Buffers, <<>>),
    Combined = <<Buffer/binary, Data/binary>>,
    case process_control_frames(Combined, State) of
        {ok, Rest, State1} ->
            {ok, State1#state{stream_buffers = Buffers#{StreamId => Rest}}};
        {transition, NextState, Rest, State1} ->
            %% State transition requested (e.g., GOAWAY received)
            {transition, NextState, State1#state{stream_buffers = Buffers#{StreamId => Rest}}};
        {error, Reason} ->
            {error, Reason, State}
    end.

process_control_frames(Data, State) ->
    case quic_h3_frame:decode(Data) of
        {ok, Frame, Rest} ->
            case handle_control_frame(Frame, State) of
                {ok, State1} ->
                    process_control_frames(Rest, State1);
                {transition, NextState, State1} ->
                    %% Signal state transition (e.g., for GOAWAY)
                    {transition, NextState, Rest, State1};
                {error, Reason} ->
                    {error, Reason}
            end;
        {more, _} ->
            {ok, Data, State}
    end.

handle_control_frame({settings, Settings}, #state{settings_received = false} = State) ->
    %% First frame on control stream must be SETTINGS
    {ok, State#state{
        peer_settings = Settings,
        settings_received = true
    }};
handle_control_frame({settings, _Settings}, #state{settings_received = true}) ->
    %% Duplicate SETTINGS frame
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"duplicate SETTINGS">>}};
handle_control_frame(_Frame, #state{settings_received = false}) ->
    %% SETTINGS must be first
    {error, {connection_error, ?H3_MISSING_SETTINGS, <<"expected SETTINGS">>}};
handle_control_frame({goaway, StreamId}, #state{goaway_id = undefined} = State) ->
    %% First GOAWAY - signal state transition to goaway_received
    {transition, goaway_received, State#state{goaway_id = StreamId}};
handle_control_frame({goaway, NewId}, #state{goaway_id = OldId}) when NewId > OldId ->
    %% GOAWAY with increasing ID is protocol error (RFC 9114 Section 5.2)
    {error, {connection_error, ?H3_ID_ERROR, <<"GOAWAY ID increased">>}};
handle_control_frame({goaway, NewId}, State) ->
    %% GOAWAY with same or lower ID - update
    {ok, State#state{goaway_id = NewId}};
handle_control_frame({max_push_id, _PushId}, State) ->
    %% We don't support push yet
    {ok, State};
handle_control_frame({cancel_push, _PushId}, State) ->
    %% We don't support push yet
    {ok, State};
handle_control_frame({data, _}, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"DATA on control stream">>}};
handle_control_frame({headers, _}, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"HEADERS on control stream">>}};
handle_control_frame({push_promise, _, _}, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"PUSH_PROMISE on control stream">>}};
handle_control_frame({unknown, Type, _Payload}, State) ->
    %% Unknown frame types are ignored if they're reserved
    case quic_h3_frame:is_reserved_frame_type(Type) of
        true -> {ok, State};
        % Also ignore non-reserved unknown types
        false -> {ok, State}
    end.

handle_encoder_stream_data(
    Data,
    #state{
        encoder_buffer = Buffer,
        qpack_decoder = Decoder
    } = State
) ->
    FullData = <<Buffer/binary, Data/binary>>,
    case quic_qpack:process_encoder_instructions(FullData, Decoder) of
        {ok, Decoder1} ->
            %% All instructions processed - retry blocked streams
            State1 = State#state{qpack_decoder = Decoder1, encoder_buffer = <<>>},
            retry_blocked_streams(State1);
        {incomplete, Rest, Decoder1} ->
            %% Partial instruction, buffer remaining data
            State1 = State#state{qpack_decoder = Decoder1, encoder_buffer = Rest},
            %% Still retry blocked streams - some may have become unblocked
            retry_blocked_streams(State1);
        {error, Reason} ->
            {error, {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, Reason}, State}
    end.

%% Retry blocked streams that may have become unblocked after encoder instructions
retry_blocked_streams(#state{blocked_streams = Blocked} = State) when map_size(Blocked) =:= 0 ->
    {ok, State};
retry_blocked_streams(
    #state{
        blocked_streams = Blocked,
        qpack_decoder = Decoder,
        quic_conn = QuicConn
    } = State
) ->
    InsertCount = quic_qpack:get_insert_count(Decoder),
    %% Find streams that can be unblocked (RIC <= InsertCount)
    {Ready, StillBlocked} = partition_blocked_streams(InsertCount, Blocked),
    State1 = State#state{blocked_streams = StillBlocked},
    %% Re-process each unblocked stream's headers
    case retry_blocked_streams_fold(maps:to_list(Ready), State1) of
        {ok, State2} ->
            {ok, State2};
        {error, {stream_reset, SId, Code}} ->
            quic:reset_stream(QuicConn, SId, Code),
            {ok, State1#state{streams = maps:remove(SId, State1#state.streams)}};
        {error, Reason} ->
            {error, Reason, State1}
    end.

%% Partition blocked streams into ready and still-blocked
partition_blocked_streams(InsertCount, Blocked) ->
    maps:fold(
        fun(StreamId, {RIC, _, _} = Val, {ReadyAcc, BlockedAcc}) ->
            case RIC =< InsertCount of
                true -> {maps:put(StreamId, Val, ReadyAcc), BlockedAcc};
                false -> {ReadyAcc, maps:put(StreamId, Val, BlockedAcc)}
            end
        end,
        {#{}, #{}},
        Blocked
    ).

retry_blocked_streams_fold([], State) ->
    {ok, State};
retry_blocked_streams_fold([{StreamId, {_RIC, HeaderBlock, Fin}} | Rest], State) ->
    %% Get stream record with proper defaults
    Stream = maps:get(
        StreamId,
        State#state.streams,
        #h3_stream{id = StreamId, type = request, state = open}
    ),
    case handle_request_frame(StreamId, {headers, HeaderBlock}, Fin, Stream, State) of
        {ok, Stream1, State1} ->
            State2 = State1#state{streams = maps:put(StreamId, Stream1, State1#state.streams)},
            retry_blocked_streams_fold(Rest, State2);
        {error, {stream_reset, _, _} = Err} ->
            %% Stream-level error - propagate to caller
            {error, Err};
        {error, Reason} ->
            %% Connection error - stop processing
            {error, Reason}
    end.

handle_decoder_stream_data(
    Data,
    #state{
        decoder_buffer = Buffer,
        qpack_encoder = Encoder
    } = State
) ->
    FullData = <<Buffer/binary, Data/binary>>,
    case quic_qpack:process_decoder_instructions(FullData, Encoder) of
        {ok, Encoder1} ->
            {ok, State#state{qpack_encoder = Encoder1, decoder_buffer = <<>>}};
        {incomplete, Rest, Encoder1} ->
            %% Partial instruction, buffer remaining data
            {ok, State#state{qpack_encoder = Encoder1, decoder_buffer = Rest}};
        {error, Reason} ->
            {error, {connection_error, ?H3_QPACK_DECODER_STREAM_ERROR, Reason}, State}
    end.

handle_request_stream_data(
    StreamId,
    Data,
    Fin,
    #state{streams = Streams, stream_buffers = Buffers} = State
) ->
    Stream = maps:get(StreamId, Streams, #h3_stream{id = StreamId, type = request, state = open}),
    Buffer = maps:get(StreamId, Buffers, <<>>),
    Combined = <<Buffer/binary, Data/binary>>,

    case process_request_frames(StreamId, Combined, Fin, Stream, State) of
        {ok, Rest, Stream1, State1} ->
            Buffers1 =
                case Rest of
                    <<>> -> maps:remove(StreamId, Buffers);
                    _ -> Buffers#{StreamId => Rest}
                end,
            Streams1 = Streams#{StreamId => Stream1},
            {ok, State1#state{streams = Streams1, stream_buffers = Buffers1}};
        {error, Reason} ->
            {error, Reason, State}
    end.

process_request_frames(StreamId, Data, Fin, Stream, #state{quic_conn = QuicConn} = State) ->
    case quic_h3_frame:decode(Data) of
        {ok, Frame, Rest} ->
            case handle_request_frame(StreamId, Frame, Fin andalso Rest =:= <<>>, Stream, State) of
                {ok, Stream1, State1} ->
                    process_request_frames(StreamId, Rest, Fin, Stream1, State1);
                {error, {stream_reset, SId, Code}} ->
                    %% Stream-level error - reset the stream and remove from tracking
                    quic:reset_stream(QuicConn, SId, Code),
                    {ok, <<>>, Stream, State#state{streams = maps:remove(SId, State#state.streams)}};
                {error, Reason} ->
                    {error, Reason}
            end;
        {more, _} ->
            {ok, Data, Stream, State}
    end.

handle_request_frame(
    StreamId,
    {headers, HeaderBlock},
    Fin,
    #h3_stream{frame_state = expecting_headers} = Stream,
    #state{qpack_decoder = Decoder, owner = Owner, role = Role} = State
) ->
    case quic_qpack:decode(HeaderBlock, Decoder) of
        {{ok, Headers}, Decoder1} ->
            %% Send Section Acknowledgment on decoder stream (RFC 9204 Section 4.4)
            State1 = send_section_ack(StreamId, State#state{qpack_decoder = Decoder1}),
            Stream1 = update_stream_with_headers(Headers, Stream),
            Stream2 =
                case Fin of
                    true -> Stream1#h3_stream{frame_state = complete, state = half_closed_remote};
                    false -> Stream1#h3_stream{frame_state = expecting_data}
                end,
            %% Notify owner and optionally call handler
            case Role of
                server ->
                    Method = Stream2#h3_stream.method,
                    Path = Stream2#h3_stream.path,
                    Owner ! {quic_h3, self(), {request, StreamId, Method, Path, Headers}},
                    %% Call handler if set
                    invoke_handler(self(), StreamId, Method, Path, Headers);
                client ->
                    Status = Stream2#h3_stream.status,
                    Owner ! {quic_h3, self(), {response, StreamId, Status, Headers}}
            end,
            {ok, Stream2, State1};
        {{blocked, RIC}, Decoder1} ->
            %% Stream blocked waiting for encoder instructions (RFC 9204 Section 2.2.2)
            %% Buffer the stream and wait for more encoder data
            BlockedStreams = maps:put(
                StreamId, {RIC, HeaderBlock, Fin}, State#state.blocked_streams
            ),
            {ok, Stream, State#state{blocked_streams = BlockedStreams, qpack_decoder = Decoder1}};
        {{error, Reason}, _Decoder1} ->
            {error, {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, Reason}}
    end;
%% DATA before HEADERS - stream error (RFC 9114 Section 4.1)
handle_request_frame(
    StreamId,
    {data, _Payload},
    _Fin,
    #h3_stream{frame_state = expecting_headers},
    _State
) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}};
%% DATA frame - validate content-length if present (RFC 9114 Section 4.1.2)
handle_request_frame(
    StreamId,
    {data, Payload},
    Fin,
    #h3_stream{frame_state = expecting_data, content_length = CL, body_received = Received} =
        Stream,
    #state{owner = Owner} = State
) when CL =/= undefined ->
    NewReceived = Received + byte_size(Payload),
    case NewReceived > CL of
        true ->
            %% Body exceeds content-length - stream error
            {error, {stream_reset, StreamId, ?H3_MESSAGE_ERROR}};
        false when Fin, NewReceived < CL ->
            %% Body shorter than content-length - stream error
            {error, {stream_reset, StreamId, ?H3_MESSAGE_ERROR}};
        false ->
            Stream1 = Stream#h3_stream{
                body = <<(Stream#h3_stream.body)/binary, Payload/binary>>,
                body_received = NewReceived
            },
            Owner ! {quic_h3, self(), {data, StreamId, Payload, Fin}},
            Stream2 =
                case Fin of
                    true -> Stream1#h3_stream{frame_state = complete, state = half_closed_remote};
                    false -> Stream1
                end,
            {ok, Stream2, State}
    end;
%% DATA frame - no content-length
handle_request_frame(
    StreamId,
    {data, Payload},
    Fin,
    #h3_stream{frame_state = expecting_data} = Stream,
    #state{owner = Owner} = State
) ->
    Stream1 = Stream#h3_stream{
        body = <<(Stream#h3_stream.body)/binary, Payload/binary>>,
        body_received = Stream#h3_stream.body_received + byte_size(Payload)
    },
    Owner ! {quic_h3, self(), {data, StreamId, Payload, Fin}},
    Stream2 =
        case Fin of
            true -> Stream1#h3_stream{frame_state = complete, state = half_closed_remote};
            false -> Stream1
        end,
    {ok, Stream2, State};
%% Non-trailer HEADERS after body started - stream error (RFC 9114 Section 4.1)
handle_request_frame(
    StreamId,
    {headers, _HeaderBlock},
    false,
    #h3_stream{frame_state = expecting_data},
    _State
) ->
    {error, {stream_reset, StreamId, ?H3_FRAME_UNEXPECTED}};
%% Trailers (HEADERS with FIN after expecting_data)
handle_request_frame(
    StreamId,
    {headers, HeaderBlock},
    true,
    #h3_stream{frame_state = expecting_data} = Stream,
    #state{qpack_decoder = Decoder, owner = Owner} = State
) ->
    case quic_qpack:decode(HeaderBlock, Decoder) of
        {{ok, Trailers}, Decoder1} ->
            %% Send Section Acknowledgment for trailers
            State1 = send_section_ack(StreamId, State#state{qpack_decoder = Decoder1}),
            Stream1 = Stream#h3_stream{
                trailers = Trailers,
                frame_state = complete,
                state = half_closed_remote
            },
            Owner ! {quic_h3, self(), {trailers, StreamId, Trailers}},
            {ok, Stream1, State1};
        {{blocked, RIC}, Decoder1} ->
            %% Trailers blocked - buffer them
            BlockedStreams = maps:put(
                StreamId, {RIC, HeaderBlock, true}, State#state.blocked_streams
            ),
            {ok, Stream, State#state{blocked_streams = BlockedStreams, qpack_decoder = Decoder1}};
        {{error, Reason}, _Decoder1} ->
            {error, {connection_error, ?H3_QPACK_DECOMPRESSION_FAILED, Reason}}
    end;
handle_request_frame(_StreamId, {settings, _}, _Fin, _Stream, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"SETTINGS on request stream">>}};
handle_request_frame(_StreamId, {goaway, _}, _Fin, _Stream, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"GOAWAY on request stream">>}};
handle_request_frame(_StreamId, {max_push_id, _}, _Fin, _Stream, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"MAX_PUSH_ID on request stream">>}};
handle_request_frame(_StreamId, {cancel_push, _}, _Fin, _Stream, _State) ->
    {error, {connection_error, ?H3_FRAME_UNEXPECTED, <<"CANCEL_PUSH on request stream">>}};
handle_request_frame(_StreamId, {unknown, _Type, _Payload}, _Fin, Stream, State) ->
    %% Skip unknown frame types
    {ok, Stream, State};
handle_request_frame(_StreamId, _Frame, _Fin, Stream, State) ->
    %% Unexpected frame in current state - skip for now
    {ok, Stream, State}.

update_stream_with_headers(Headers, Stream) ->
    lists:foldl(
        fun
            ({<<":method">>, Value}, S) ->
                S#h3_stream{method = Value};
            ({<<":path">>, Value}, S) ->
                S#h3_stream{path = Value};
            ({<<":scheme">>, Value}, S) ->
                S#h3_stream{scheme = Value};
            ({<<":authority">>, Value}, S) ->
                S#h3_stream{authority = Value};
            ({<<":status">>, Value}, S) ->
                Status = binary_to_integer(Value),
                S#h3_stream{status = Status};
            ({<<"content-length">>, Value}, S) ->
                S#h3_stream{content_length = binary_to_integer(Value)};
            (_, S) ->
                S
        end,
        Stream#h3_stream{headers = Headers},
        Headers
    ).

handle_stream_closed(
    StreamId,
    #state{
        streams = Streams,
        stream_buffers = Buffers,
        uni_stream_buffers = UniBuffers
    } = State
) ->
    case is_critical_stream(StreamId, State) of
        {true, Type} ->
            %% Peer closed a critical stream - connection error (RFC 9114 Section 6.2.1)
            {error,
                {connection_error, ?H3_CLOSED_CRITICAL_STREAM,
                    iolist_to_binary(io_lib:format("~p stream closed", [Type]))}};
        false ->
            %% Normal stream - remove from tracking
            {ok, State#state{
                streams = maps:remove(StreamId, Streams),
                stream_buffers = maps:remove(StreamId, Buffers),
                uni_stream_buffers = maps:remove(StreamId, UniBuffers)
            }}
    end.

%% Check if a stream is a critical H3 stream
is_critical_stream(StreamId, #state{peer_control_stream = StreamId}) -> {true, control};
is_critical_stream(StreamId, #state{peer_encoder_stream = StreamId}) -> {true, qpack_encoder};
is_critical_stream(StreamId, #state{peer_decoder_stream = StreamId}) -> {true, qpack_decoder};
is_critical_stream(_, _) -> false.

%%====================================================================
%% Internal: Sending
%%====================================================================

send_request(
    Headers,
    _Opts,
    #state{
        quic_conn = QuicConn,
        qpack_encoder = Encoder,
        next_stream_id = NextId,
        streams = Streams
    } = State
) ->
    case quic:open_stream(QuicConn) of
        {ok, StreamId} ->
            {Encoded, Encoder1} = quic_qpack:encode(Headers, Encoder),
            HeadersFrame = quic_h3_frame:encode_headers(Encoded),
            case quic:send_data(QuicConn, StreamId, HeadersFrame, false) of
                ok ->
                    Stream = #h3_stream{
                        id = StreamId,
                        type = request,
                        state = open,
                        frame_state = expecting_headers
                    },
                    State1 = State#state{
                        qpack_encoder = Encoder1,
                        next_stream_id = NextId + 4,
                        streams = Streams#{StreamId => Stream}
                    },
                    %% Send encoder instructions if any
                    send_encoder_instructions(State1),
                    {ok, StreamId, State1};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

do_send_response(
    StreamId,
    Status,
    Headers,
    #state{
        quic_conn = QuicConn,
        qpack_encoder = Encoder,
        streams = Streams
    } = State
) ->
    case maps:find(StreamId, Streams) of
        {ok, Stream} ->
            StatusHeader = {<<":status">>, integer_to_binary(Status)},
            AllHeaders = [StatusHeader | Headers],
            {Encoded, Encoder1} = quic_qpack:encode(AllHeaders, Encoder),
            HeadersFrame = quic_h3_frame:encode_headers(Encoded),
            case quic:send_data(QuicConn, StreamId, HeadersFrame, false) of
                ok ->
                    Stream1 = Stream#h3_stream{status = Status, headers = AllHeaders},
                    State1 = State#state{
                        qpack_encoder = Encoder1,
                        streams = Streams#{StreamId => Stream1}
                    },
                    send_encoder_instructions(State1),
                    {ok, State1};
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            {error, unknown_stream}
    end.

do_send_data(StreamId, Data, Fin, #state{quic_conn = QuicConn, streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, Stream} ->
            DataFrame = quic_h3_frame:encode_data(Data),
            case quic:send_data(QuicConn, StreamId, DataFrame, Fin) of
                ok ->
                    Stream1 =
                        case Fin of
                            true -> Stream#h3_stream{state = half_closed_local};
                            false -> Stream
                        end,
                    {ok, State#state{streams = Streams#{StreamId => Stream1}}};
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            {error, unknown_stream}
    end.

do_send_trailers(
    StreamId,
    Trailers,
    #state{
        quic_conn = QuicConn,
        qpack_encoder = Encoder,
        streams = Streams
    } = State
) ->
    case maps:find(StreamId, Streams) of
        {ok, Stream} ->
            {Encoded, Encoder1} = quic_qpack:encode(Trailers, Encoder),
            TrailersFrame = quic_h3_frame:encode_headers(Encoded),
            case quic:send_data(QuicConn, StreamId, TrailersFrame, true) of
                ok ->
                    Stream1 = Stream#h3_stream{
                        trailers = Trailers,
                        state = half_closed_local
                    },
                    State1 = State#state{
                        qpack_encoder = Encoder1,
                        streams = Streams#{StreamId => Stream1}
                    },
                    send_encoder_instructions(State1),
                    {ok, State1};
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            {error, unknown_stream}
    end.

do_cancel_stream(StreamId, ErrorCode, #state{quic_conn = QuicConn, streams = Streams} = State) ->
    quic:reset_stream(QuicConn, StreamId, ErrorCode),
    State#state{streams = maps:remove(StreamId, Streams)}.

send_goaway(
    #state{
        quic_conn = QuicConn,
        local_control_stream = ControlStream,
        last_stream_id = LastId
    } = State
) ->
    GoawayFrame = quic_h3_frame:encode_goaway(LastId),
    case quic:send_data(QuicConn, ControlStream, GoawayFrame, false) of
        ok ->
            {ok, State#state{goaway_id = LastId}};
        {error, Reason} ->
            {error, Reason}
    end.

send_encoder_instructions(
    #state{
        quic_conn = QuicConn,
        local_encoder_stream = EncoderStream,
        qpack_encoder = Encoder
    } = State
) ->
    Instructions = quic_qpack:get_encoder_instructions(Encoder),
    case Instructions of
        <<>> ->
            State;
        _ ->
            quic:send_data(QuicConn, EncoderStream, Instructions, false),
            Encoder1 = quic_qpack:clear_encoder_instructions(Encoder),
            State#state{qpack_encoder = Encoder1}
    end.

%%====================================================================
%% Internal: Helpers
%%====================================================================

%% Send Section Acknowledgment on decoder stream (RFC 9204 Section 4.4)
send_section_ack(
    StreamId,
    #state{
        quic_conn = QuicConn,
        local_decoder_stream = DecoderStream
    } = State
) when DecoderStream =/= undefined ->
    Ack = quic_qpack:encode_section_ack(StreamId),
    quic:send_data(QuicConn, DecoderStream, Ack, false),
    State;
send_section_ack(_StreamId, State) ->
    %% Decoder stream not yet established
    State.

maybe_transition_connected(#state{settings_received = true} = State) ->
    {next_state, connected, State};
maybe_transition_connected(State) ->
    {keep_state, State}.

maybe_close_if_drained(#state{streams = Streams} = State) when map_size(Streams) =:= 0 ->
    {next_state, closing, State};
maybe_close_if_drained(State) ->
    {keep_state, State}.

handle_connection_error(
    {connection_error, ErrorCode, Reason}, #state{quic_conn = QuicConn, owner = Owner} = State
) ->
    Owner ! {quic_h3, self(), {error, ErrorCode, Reason}},
    catch quic:close(QuicConn, ErrorCode, Reason),
    {next_state, closing, State}.

notify_stream_reset(StreamId, ErrorCode, #state{owner = Owner}) ->
    Owner ! {quic_h3, self(), {stream_reset, StreamId, ErrorCode}}.

invoke_handler(Conn, StreamId, Method, Path, Headers) ->
    case get(h3_handler) of
        undefined ->
            ok;
        Fun when is_function(Fun, 5) ->
            %% Spawn to avoid blocking the connection process
            spawn(fun() ->
                try
                    Fun(Conn, StreamId, Method, Path, Headers)
                catch
                    Class:Reason:Stack ->
                        error_logger:error_msg(
                            "HTTP/3 handler error: ~p:~p~n~p~n",
                            [Class, Reason, Stack]
                        )
                end
            end);
        Module when is_atom(Module) ->
            spawn(fun() ->
                try
                    Module:handle_request(Conn, StreamId, Method, Path, Headers)
                catch
                    Class:Reason:Stack ->
                        error_logger:error_msg(
                            "HTTP/3 handler error: ~p:~p~n~p~n",
                            [Class, Reason, Stack]
                        )
                end
            end)
    end.
