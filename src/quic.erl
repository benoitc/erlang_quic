%%% -*- erlang -*-
%%%
%%% Pure Erlang QUIC implementation
%%% RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC public API.
%%%
%%% This module provides the public interface for QUIC connections.
%%% The API is compatible with hackney_quic for drop-in replacement.
%%%
%%% == Messages ==
%%%
%%% Messages sent to owner process:
%%% <ul>
%%%   <li>`{quic, ConnRef, {connected, Info}}' - Connection established</li>
%%%   <li>`{quic, ConnRef, {stream_opened, StreamId}}' - Stream opened</li>
%%%   <li>`{quic, ConnRef, {closed, Reason}}' - Connection closed</li>
%%%   <li>`{quic, ConnRef, {transport_error, Code, Reason}}' - Transport error</li>
%%%   <li>`{quic, ConnRef, {stream_data, StreamId, Bin, Fin}}' - Data received</li>
%%%   <li>`{quic, ConnRef, {stream_reset, StreamId, ErrorCode}}' - Stream reset</li>
%%%   <li>`{quic, ConnRef, {stop_sending, StreamId, ErrorCode}}' - Stop sending</li>
%%%   <li>`{quic, ConnRef, {goaway, LastStreamId, ErrorCode, Debug}}' - GoAway received</li>
%%%   <li>`{quic, ConnRef, {session_ticket, Ticket}}' - Session ticket for 0-RTT</li>
%%%   <li>`{quic, ConnRef, {send_ready, StreamId}}' - Stream ready to write</li>
%%%   <li>`{quic, ConnRef, {timer, NextTimeoutMs}}' - Timer notification</li>
%%%   <li>`{quic, ConnRef, {datagram, Data}}' - Datagram received (RFC 9221)</li>
%%% </ul>
%%%

-module(quic).

-export([
    connect/4,
    close/2,
    open_stream/1,
    open_unidirectional_stream/1,
    send_data/4,
    reset_stream/3,
    handle_timeout/2,
    process/1,
    peername/1,
    sockname/1,
    peercert/1,
    set_owner/2,
    send_datagram/2,
    setopts/2,
    migrate/1,
    %% Stream prioritization (RFC 9218)
    set_stream_priority/4,
    get_stream_priority/2
]).

%% Server management API
-export([
    start_server/3,
    stop_server/1,
    get_server_info/1,
    get_server_port/1,
    get_server_connections/1,
    which_servers/0
]).

-export([is_available/0, get_fd/1]).

%%====================================================================
%% API
%%====================================================================

%% @doc Check if QUIC support is available.
%% Always returns true for pure Erlang implementation.
-spec is_available() -> boolean().
is_available() ->
    %% Check that required crypto algorithms are available
    try
        Algos = crypto:supports(),
        Ciphers = proplists:get_value(ciphers, Algos, []),
        Macs = proplists:get_value(macs, Algos, []),
        HasAES = lists:member(aes_128_gcm, Ciphers) orelse
                 lists:member(aes_gcm, Ciphers),
        HasSHA256 = lists:member(hmac, Macs),
        HasAES andalso HasSHA256
    catch
        _:_ -> false
    end.

%% @doc Get the file descriptor from a gen_udp socket.
%% This can be used to pass an existing UDP socket to connect/4
%% via the `socket_fd' option.
-spec get_fd(gen_udp:socket()) -> {ok, integer()} | {error, term()}.
get_fd(Socket) ->
    case inet:getfd(Socket) of
        {ok, Fd} -> {ok, Fd};
        Error -> Error
    end.

%% @doc Connect to a QUIC server.
%% Returns {ok, ConnRef} on success where ConnRef is a reference().
%% The owner process will receive {quic, ConnRef, {connected, Info}}
%% when the connection is established.
%%
%% Options:
%% <ul>
%%   <li>`socket_fd' - Use an existing UDP socket FD (see `get_fd/1')</li>
%%   <li>`verify' - Verify server certificate (default: false)</li>
%%   <li>`alpn' - ALPN protocols (default: [&lt;&lt;"h3"&gt;&gt;])</li>
%%   <li>`sni' - Server Name Indication (default: Host)</li>
%% </ul>
-spec connect(Host, Port, Opts, Owner) -> {ok, reference()} | {error, term()}
    when Host :: binary() | string(),
         Port :: inet:port_number(),
         Opts :: map(),
         Owner :: pid().
connect(Host, Port, Opts, Owner) when is_list(Host) ->
    connect(list_to_binary(Host), Port, Opts, Owner);
connect(Host, Port, Opts, Owner) when is_binary(Host), is_integer(Port),
                                       Port > 0, Port =< 65535,
                                       is_map(Opts), is_pid(Owner) ->
    case quic_connection:start_link(Host, Port, Opts, Owner) of
        {ok, Pid} ->
            ConnRef = gen_statem:call(Pid, get_ref),
            {ok, ConnRef};
        Error ->
            Error
    end;
connect(_Host, _Port, _Opts, _Owner) ->
    {error, badarg}.

%% @doc Close a QUIC connection.
-spec close(ConnRef, Reason) -> ok
    when ConnRef :: reference() | pid(),
         Reason :: term().
close(ConnRef, Reason) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:close(Pid, Reason);
        error -> ok
    end;
close(ConnPid, Reason) when is_pid(ConnPid) ->
    quic_connection:close(ConnPid, Reason).

%% @doc Open a new bidirectional stream.
%% Returns {ok, StreamId} on success.
-spec open_stream(ConnRef) -> {ok, non_neg_integer()} | {error, term()}
    when ConnRef :: reference() | pid().
open_stream(ConnRef) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:open_stream(Pid);
        error -> {error, not_found}
    end;
open_stream(ConnPid) when is_pid(ConnPid) ->
    quic_connection:open_stream(ConnPid).

%% @doc Open a new unidirectional stream.
%% Returns {ok, StreamId} on success.
%% Unidirectional streams are send-only for the initiator.
-spec open_unidirectional_stream(ConnRef) -> {ok, non_neg_integer()} | {error, term()}
    when ConnRef :: reference() | pid().
open_unidirectional_stream(ConnRef) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:open_unidirectional_stream(Pid);
        error -> {error, not_found}
    end;
open_unidirectional_stream(ConnPid) when is_pid(ConnPid) ->
    quic_connection:open_unidirectional_stream(ConnPid).

%% @doc Send data on a stream.
%% Fin indicates if this is the final frame on the stream.
-spec send_data(ConnRef, StreamId, Data, Fin) -> ok | {error, term()}
    when ConnRef :: reference() | pid(),
         StreamId :: non_neg_integer(),
         Data :: iodata(),
         Fin :: boolean().
send_data(ConnRef, StreamId, Data, Fin) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:send_data(Pid, StreamId, Data, Fin);
        error -> {error, not_found}
    end;
send_data(ConnPid, StreamId, Data, Fin) when is_pid(ConnPid) ->
    quic_connection:send_data(ConnPid, StreamId, Data, Fin);
send_data(_ConnRef, _StreamId, _Data, _Fin) ->
    {error, badarg}.

%% @doc Reset a stream with an error code.
-spec reset_stream(ConnRef, StreamId, ErrorCode) -> ok | {error, term()}
    when ConnRef :: reference() | pid(),
         StreamId :: non_neg_integer(),
         ErrorCode :: non_neg_integer().
reset_stream(ConnRef, StreamId, ErrorCode) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:reset_stream(Pid, StreamId, ErrorCode);
        error -> {error, not_found}
    end;
reset_stream(ConnPid, StreamId, ErrorCode) when is_pid(ConnPid) ->
    quic_connection:reset_stream(ConnPid, StreamId, ErrorCode);
reset_stream(_ConnRef, _StreamId, _ErrorCode) ->
    {error, badarg}.

%% @doc Handle connection timeout.
%% Should be called when timer expires.
%% Returns next timeout in ms or 'infinity'.
-spec handle_timeout(ConnRef, NowMs) -> non_neg_integer() | infinity
    when ConnRef :: reference() | pid(),
         NowMs :: non_neg_integer().
handle_timeout(ConnRef, NowMs) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:handle_timeout(Pid, NowMs);
        error -> infinity
    end;
handle_timeout(ConnPid, NowMs) when is_pid(ConnPid) ->
    quic_connection:handle_timeout(ConnPid, NowMs);
handle_timeout(_ConnRef, _NowMs) ->
    infinity.

%% @doc Process pending QUIC events.
%% This is called automatically by the connection process.
%% Returns the next timeout in milliseconds, or 'infinity'.
-spec process(ConnRef) -> non_neg_integer() | infinity
    when ConnRef :: reference() | pid().
process(ConnRef) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:process(Pid);
        error -> infinity
    end;
process(ConnPid) when is_pid(ConnPid) ->
    quic_connection:process(ConnPid).

%% @doc Get the remote address of the connection.
-spec peername(ConnRef) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}
    when ConnRef :: reference() | pid().
peername(ConnRef) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:peername(Pid);
        error -> {error, not_found}
    end;
peername(ConnPid) when is_pid(ConnPid) ->
    quic_connection:peername(ConnPid).

%% @doc Get the local address of the connection.
-spec sockname(ConnRef) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}
    when ConnRef :: reference() | pid().
sockname(ConnRef) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:sockname(Pid);
        error -> {error, not_found}
    end;
sockname(ConnPid) when is_pid(ConnPid) ->
    quic_connection:sockname(ConnPid).

%% @doc Get the peer certificate.
%% Returns the DER-encoded certificate of the peer if available.
-spec peercert(ConnRef) -> {ok, binary()} | {error, term()}
    when ConnRef :: reference() | pid().
peercert(ConnRef) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:peercert(Pid);
        error -> {error, not_found}
    end;
peercert(ConnPid) when is_pid(ConnPid) ->
    quic_connection:peercert(ConnPid).

%% @doc Set the owner process for a connection.
%% Similar to gen_tcp:controlling_process/2.
-spec set_owner(ConnRef, NewOwner) -> ok | {error, term()}
    when ConnRef :: reference() | pid(),
         NewOwner :: pid().
set_owner(ConnRef, NewOwner) when is_reference(ConnRef), is_pid(NewOwner) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:set_owner(Pid, NewOwner);
        error -> {error, not_found}
    end;
set_owner(ConnPid, NewOwner) when is_pid(ConnPid), is_pid(NewOwner) ->
    quic_connection:set_owner(ConnPid, NewOwner);
set_owner(_ConnRef, _NewOwner) ->
    {error, badarg}.

%% @doc Send a datagram on the connection.
%% Datagrams are unreliable and may be lost.
-spec send_datagram(ConnRef, Data) -> ok | {error, term()}
    when ConnRef :: reference() | pid(),
         Data :: iodata().
send_datagram(ConnRef, Data) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:send_datagram(Pid, Data);
        error -> {error, not_found}
    end;
send_datagram(ConnPid, Data) when is_pid(ConnPid) ->
    quic_connection:send_datagram(ConnPid, Data);
send_datagram(_ConnRef, _Data) ->
    {error, badarg}.

%% @doc Set connection options.
-spec setopts(ConnRef, Opts) -> ok | {error, term()}
    when ConnRef :: reference() | pid(),
         Opts :: [{atom(), term()}].
setopts(ConnRef, Opts) when is_reference(ConnRef), is_list(Opts) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:setopts(Pid, Opts);
        error -> {error, not_found}
    end;
setopts(ConnPid, Opts) when is_pid(ConnPid), is_list(Opts) ->
    quic_connection:setopts(ConnPid, Opts);
setopts(_ConnRef, _Opts) ->
    {error, badarg}.

%% @doc Trigger connection migration to a new local address.
%% This initiates path validation on a new network path.
%% The connection will send PATH_CHALLENGE and wait for PATH_RESPONSE.
-spec migrate(ConnRef) -> ok | {error, term()}
    when ConnRef :: reference() | pid().
migrate(ConnRef) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:migrate(Pid);
        error -> {error, not_found}
    end;
migrate(ConnPid) when is_pid(ConnPid) ->
    quic_connection:migrate(ConnPid);
migrate(_ConnRef) ->
    {error, badarg}.

%% @doc Set the priority for a stream.
%% Urgency: 0-7 (lower = more urgent, default 3)
%% Incremental: boolean (data can be processed incrementally, default false)
%% Per RFC 9218 (Extensible Priorities for HTTP).
-spec set_stream_priority(ConnRef, StreamId, Urgency, Incremental) -> ok | {error, term()}
    when ConnRef :: reference() | pid(),
         StreamId :: non_neg_integer(),
         Urgency :: 0..7,
         Incremental :: boolean().
set_stream_priority(ConnRef, StreamId, Urgency, Incremental) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:set_stream_priority(Pid, StreamId, Urgency, Incremental);
        error -> {error, not_found}
    end;
set_stream_priority(ConnPid, StreamId, Urgency, Incremental) when is_pid(ConnPid) ->
    quic_connection:set_stream_priority(ConnPid, StreamId, Urgency, Incremental);
set_stream_priority(_ConnRef, _StreamId, _Urgency, _Incremental) ->
    {error, badarg}.

%% @doc Get the priority for a stream.
%% Returns {ok, {Urgency, Incremental}} or {error, not_found}.
-spec get_stream_priority(ConnRef, StreamId) -> {ok, {0..7, boolean()}} | {error, term()}
    when ConnRef :: reference() | pid(),
         StreamId :: non_neg_integer().
get_stream_priority(ConnRef, StreamId) when is_reference(ConnRef) ->
    case quic_connection:lookup(ConnRef) of
        {ok, Pid} -> quic_connection:get_stream_priority(Pid, StreamId);
        error -> {error, not_found}
    end;
get_stream_priority(ConnPid, StreamId) when is_pid(ConnPid) ->
    quic_connection:get_stream_priority(ConnPid, StreamId);
get_stream_priority(_ConnRef, _StreamId) ->
    {error, badarg}.

%%====================================================================
%% Server Management API
%%====================================================================

%% @doc Start a named QUIC server on the specified port.
%%
%% Creates a listener pool that accepts incoming QUIC connections.
%% Multiple named servers can run on different ports.
%%
%% Options:
%% <ul>
%%   <li>`cert' - DER-encoded certificate (required)</li>
%%   <li>`key' - Private key term (required)</li>
%%   <li>`alpn' - List of ALPN protocols (default: [&lt;&lt;"h3"&gt;&gt;])</li>
%%   <li>`pool_size' - Number of listener processes (default: 1)</li>
%%   <li>`connection_handler' - Fun(ConnPid, ConnRef) -> {ok, HandlerPid}</li>
%% </ul>
%%
%% Example:
%% ```
%% {ok, _} = quic:start_server(my_server, 4433, #{
%%     cert => CertDer,
%%     key => KeyTerm,
%%     alpn => [<<"h3">>],
%%     pool_size => 4
%% }).
%% '''
-spec start_server(Name, Port, Opts) -> {ok, pid()} | {error, term()}
    when Name :: atom(),
         Port :: inet:port_number(),
         Opts :: map().
start_server(Name, Port, Opts) when is_atom(Name), is_integer(Port),
                                    Port >= 0, Port =< 65535, is_map(Opts) ->
    quic_server_sup:start_server(Name, Port, Opts);
start_server(_Name, _Port, _Opts) ->
    {error, badarg}.

%% @doc Stop a named QUIC server.
%%
%% Stops the server and all its connections.
%% The port will be freed for reuse.
-spec stop_server(Name) -> ok | {error, term()}
    when Name :: atom().
stop_server(Name) when is_atom(Name) ->
    quic_server_sup:stop_server(Name);
stop_server(_Name) ->
    {error, badarg}.

%% @doc Get information about a named server.
%%
%% Returns a map containing:
%% <ul>
%%   <li>`pid' - Server supervisor PID</li>
%%   <li>`port' - Listening port</li>
%%   <li>`opts' - Server options</li>
%%   <li>`started_at' - Start timestamp in milliseconds</li>
%% </ul>
-spec get_server_info(Name) -> {ok, map()} | {error, not_found}
    when Name :: atom().
get_server_info(Name) when is_atom(Name) ->
    quic_server_registry:lookup(Name);
get_server_info(_Name) ->
    {error, badarg}.

%% @doc Get the listening port of a named server.
%%
%% Useful when the server was started with port 0 (ephemeral port).
-spec get_server_port(Name) -> {ok, inet:port_number()} | {error, not_found}
    when Name :: atom().
get_server_port(Name) when is_atom(Name) ->
    quic_server_registry:get_port(Name);
get_server_port(_Name) ->
    {error, badarg}.

%% @doc Get the list of connection PIDs for a named server.
-spec get_server_connections(Name) -> {ok, [pid()]} | {error, not_found}
    when Name :: atom().
get_server_connections(Name) when is_atom(Name) ->
    quic_server_registry:get_connections(Name);
get_server_connections(_Name) ->
    {error, badarg}.

%% @doc List all running server names.
-spec which_servers() -> [atom()].
which_servers() ->
    quic_server_registry:list().
