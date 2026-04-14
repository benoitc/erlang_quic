%%% -*- erlang -*-
%%%
%%% HTTP/3 public API (RFC 9114)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc HTTP/3 client and server API.
%%%
%%% This module provides the public interface for HTTP/3 connections
%%% built on top of QUIC transport.
%%%
%%% == Client Usage ==
%%%
%%% ```
%%% %% Connect to an HTTP/3 server
%%% {ok, Conn} = quic_h3:connect("example.com", 443),
%%%
%%% %% Send a request
%%% Headers = [
%%%     {<<":method">>, <<"GET">>},
%%%     {<<":scheme">>, <<"https">>},
%%%     {<<":path">>, <<"/">>},
%%%     {<<":authority">>, <<"example.com">>}
%%% ],
%%% {ok, StreamId} = quic_h3:request(Conn, Headers),
%%%
%%% %% Receive response (async messages to owner)
%%% receive
%%%     {quic_h3, Conn, {response, StreamId, Status, RespHeaders}} ->
%%%         io:format("Status: ~p~n", [Status])
%%% end,
%%%
%%% %% Close connection
%%% ok = quic_h3:close(Conn).
%%% '''
%%%
%%% == Server Usage ==
%%%
%%% ```
%%% %% Start an HTTP/3 server
%%% {ok, _} = quic_h3:start_server(my_server, 4433, #{
%%%     cert => CertDer,
%%%     key => KeyTerm,
%%%     handler => fun handle_request/5
%%% }),
%%%
%%% %% Handler function
%%% handle_request(Conn, StreamId, Method, Path, Headers) ->
%%%     quic_h3:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
%%%     quic_h3:send_data(Conn, StreamId, <<"Hello, HTTP/3!">>, true).
%%% '''
%%%
%%% == Server Push (RFC 9114 Section 4.6) ==
%%%
%%% Server push allows a server to pre-emptively send resources to a client.
%%%
%%% Server side:
%%% ```
%%% %% In request handler, push associated resources
%%% {ok, PushId} = quic_h3:push(Conn, StreamId, [
%%%     {<<":method">>, <<"GET">>},
%%%     {<<":scheme">>, <<"https">>},
%%%     {<<":authority">>, <<"example.com">>},
%%%     {<<":path">>, <<"/style.css">>}
%%% ]),
%%% ok = quic_h3:send_push_response(Conn, PushId, 200,
%%%     [{<<"content-type">>, <<"text/css">>}]),
%%% ok = quic_h3:send_push_data(Conn, PushId, CssBody, true).
%%% '''
%%%
%%% Client side:
%%% ```
%%% %% Enable push after connecting
%%% ok = quic_h3:set_max_push_id(Conn, 10),
%%%
%%% %% Handle push notifications
%%% receive
%%%     {quic_h3, Conn, {push_promise, PushId, ReqStreamId, Headers}} ->
%%%         %% Server announced it will push this resource
%%%         ok;
%%%     {quic_h3, Conn, {push_response, PushId, Status, Headers}} ->
%%%         %% Push response headers received
%%%         ok;
%%%     {quic_h3, Conn, {push_data, PushId, Data, Fin}} ->
%%%         %% Push response data received
%%%         ok
%%% end.
%%% '''
%%%
%%% @end

-module(quic_h3).

%% Client API
-export([
    connect/2,
    connect/3,
    request/2,
    request/3,
    wait_connected/2
]).

%% Shared API (client and server)
-export([
    send_data/3,
    send_data/4,
    send_trailers/3,
    cancel/2,
    cancel/3,
    goaway/1,
    close/1,
    %% Per-stream handler registration
    set_stream_handler/3,
    set_stream_handler/4,
    unset_stream_handler/2,
    %% HTTP Datagrams (RFC 9297)
    send_datagram/3,
    h3_datagrams_enabled/1,
    max_datagram_size/2
]).

%% Server API
-export([
    start_server/3,
    stop_server/1,
    send_response/4
]).

%% Server Push API (RFC 9114 Section 4.6)
-export([
    push/3,
    send_push_response/4,
    send_push_data/4
]).

%% Client Push API
-export([
    set_max_push_id/2,
    cancel_push/2
]).

%% Internal callbacks
-export([
    h3_connection_handler/2
]).

%% Query API
-export([
    get_settings/1,
    get_peer_settings/1,
    get_quic_conn/1
]).

%% Types
-export_type([
    conn/0,
    stream_id/0,
    headers/0,
    status/0,
    error_code/0,
    connect_opts/0,
    server_opts/0,
    push_id/0
]).

-include("quic.hrl").
-include("quic_h3.hrl").

%%====================================================================
%% Types
%%====================================================================

-type conn() :: pid().
-type stream_id() :: non_neg_integer().
-type push_id() :: non_neg_integer().
-type headers() :: [{binary(), binary()}].
-type status() :: 100..599.
-type error_code() :: non_neg_integer().

-type stream_type_handler() ::
    fun((uni | bidi, stream_id(), non_neg_integer()) -> claim | ignore).

-type connect_opts() :: #{
    %% TLS options
    cert => binary(),
    key => term(),
    cacerts => [binary()],
    verify => verify_none | verify_peer,
    %% HTTP/3 settings
    settings => map(),
    %% QUIC options
    quic_opts => map(),
    %% Extension hook for unknown uni-stream types (e.g. WebTransport).
    stream_type_handler => stream_type_handler()
}.

%% Override function invoked once per newly accepted QUIC connection.
%% Keys absent from the returned map inherit the listener-wide values.
-type connection_handler_fun() ::
    fun((QuicConnPid :: pid()) -> per_connection_opts()).

-type per_connection_opts() :: #{
    owner => pid(),
    handler => fun((conn(), stream_id(), binary(), binary(), headers()) -> any()) | module(),
    settings => map(),
    stream_type_handler => stream_type_handler(),
    h3_datagram_enabled => boolean()
}.

-type server_opts() :: #{
    %% TLS (required)
    cert := binary(),
    key := term(),
    %% Handler
    handler => fun((conn(), stream_id(), binary(), binary(), headers()) -> any()) | module(),
    %% HTTP/3 settings
    settings => map(),
    %% QUIC options
    quic_opts => map(),
    %% Extension hook for unknown uni-stream types (e.g. WebTransport).
    stream_type_handler => stream_type_handler(),
    %% Per-connection configuration override; the returned map's
    %% `owner', `handler', `stream_type_handler', `h3_datagram_enabled',
    %% and `settings' keys replace the listener-wide defaults for that
    %% single connection. Useful for spawning a dedicated router pid
    %% per H3 connection rather than sharing one global owner.
    connection_handler => connection_handler_fun()
}.

%%====================================================================
%% Client API
%%====================================================================

%% @doc Connect to an HTTP/3 server.
%%
%% Establishes a QUIC connection with ALPN "h3" and starts
%% the HTTP/3 connection layer.
%%
%% The calling process becomes the owner and will receive
%% HTTP/3 events as messages.
%% @end
-spec connect(Host, Port) -> {ok, conn()} | {error, term()} when
    Host :: binary() | string() | inet:ip_address(),
    Port :: inet:port_number().
connect(Host, Port) ->
    connect(Host, Port, #{}).

%% @doc Connect to an HTTP/3 server with options.
%%
%% Options:
%% <ul>
%%   <li>`sync' - If `true', wait for H3 connection to be established before returning.
%%                This ensures requests can be made immediately. Default: `false'.</li>
%%   <li>`connect_timeout' - Timeout in ms for sync connect. Default: 5000.</li>
%% </ul>
%% @end
-spec connect(Host, Port, Opts) -> {ok, conn()} | {error, term()} when
    Host :: binary() | string() | inet:ip_address(),
    Port :: inet:port_number(),
    Opts :: connect_opts().
connect(Host, Port, Opts) ->
    HostBin = to_binary(Host),
    QuicOpts = build_client_quic_opts(HostBin, Opts),
    case quic:connect(HostBin, Port, QuicOpts, self()) of
        {ok, QuicConn} ->
            start_h3_connection(QuicConn, HostBin, Port, Opts);
        {error, Reason} ->
            {error, Reason}
    end.

start_h3_connection(QuicConn, HostBin, Port, Opts) ->
    H3Opts = maps:with([settings, stream_type_handler, h3_datagram_enabled], Opts),
    case quic_h3_connection:start_link(QuicConn, HostBin, Port, H3Opts) of
        {ok, H3Conn} ->
            %% Transfer ownership to H3 process so it receives QUIC events
            ok = quic:set_owner_sync(QuicConn, H3Conn),
            maybe_wait_connected(H3Conn, Opts);
        {error, Reason} ->
            quic:close(QuicConn, 0, <<"h3 init failed">>),
            {error, Reason}
    end.

maybe_wait_connected(H3Conn, Opts) ->
    case maps:get(sync, Opts, false) of
        true ->
            Timeout = maps:get(connect_timeout, Opts, 5000),
            case wait_connected(H3Conn, Timeout) of
                ok ->
                    {ok, H3Conn};
                {error, timeout} ->
                    quic_h3:close(H3Conn),
                    {error, connect_timeout}
            end;
        false ->
            {ok, H3Conn}
    end.

%% @doc Send an HTTP request.
%%
%% Opens a new request stream and sends the HEADERS frame.
%% Returns the stream ID for tracking the response.
%%
%% Required pseudo-headers:
%% <ul>
%%   <li>`:method' - HTTP method (GET, POST, etc.)</li>
%%   <li>`:scheme' - URL scheme (https)</li>
%%   <li>`:path' - Request path</li>
%%   <li>`:authority' - Host authority</li>
%% </ul>
%% @end
-spec request(conn(), headers()) -> {ok, stream_id()} | {error, term()}.
request(Conn, Headers) ->
    quic_h3_connection:request(Conn, Headers).

%% @doc Send an HTTP request with options.
-spec request(conn(), headers(), map()) -> {ok, stream_id()} | {error, term()}.
request(Conn, Headers, Opts) ->
    quic_h3_connection:request(Conn, Headers, Opts).

%%====================================================================
%% Shared API (Client and Server)
%%====================================================================

%% @doc Send body data on a request stream.
%%
%% For clients, this sends request body data.
%% For servers, this sends response body data.
%% @end
-spec send_data(conn(), stream_id(), binary()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data) ->
    quic_h3_connection:send_data(Conn, StreamId, Data).

%% @doc Send body data with fin flag.
%%
%% Set `Fin' to `true' to indicate the end of the body.
%% @end
-spec send_data(conn(), stream_id(), binary(), boolean()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data, Fin) ->
    quic_h3_connection:send_data(Conn, StreamId, Data, Fin).

%% @doc Send trailers on a request stream.
%%
%% Trailers are sent after the body and signal the end of the stream.
%% @end
-spec send_trailers(conn(), stream_id(), headers()) -> ok | {error, term()}.
send_trailers(Conn, StreamId, Trailers) ->
    quic_h3_connection:send_trailers(Conn, StreamId, Trailers).

%% @doc Cancel a stream with H3_REQUEST_CANCELLED error.
-spec cancel(conn(), stream_id()) -> ok.
cancel(Conn, StreamId) ->
    quic_h3_connection:cancel_stream(Conn, StreamId).

%% @doc Cancel a stream with a specific error code.
-spec cancel(conn(), stream_id(), error_code()) -> ok.
cancel(Conn, StreamId, ErrorCode) ->
    quic_h3_connection:cancel_stream(Conn, StreamId, ErrorCode).

%% @doc Initiate graceful shutdown.
%%
%% Sends a GOAWAY frame to the peer. No new requests will be
%% accepted, but existing streams will complete.
%% @end
-spec goaway(conn()) -> ok.
goaway(Conn) ->
    quic_h3_connection:goaway(Conn).

%% @doc Close the connection.
%%
%% Immediately closes the HTTP/3 connection and underlying QUIC connection.
%% @end
-spec close(conn()) -> ok.
close(Conn) ->
    quic_h3_connection:close(Conn).

%% @doc Register a handler to receive stream body data.
%%
%% By default, body data messages are sent to the connection owner.
%% For server handlers that need to receive body data (e.g., POST bodies),
%% call this function to redirect data to the handler process.
%%
%% The handler will receive messages of the form:
%% `{quic_h3, Conn, {data, StreamId, Data, Fin}}'
%%
%% If data arrived before registration, it is returned as a list of
%% `{Data, Fin}' tuples that the handler should process.
%%
%% Example:
%% ```
%% handle_request(Conn, StreamId, <<"POST">>, _Path, _Headers) ->
%%     case quic_h3:set_stream_handler(Conn, StreamId, self()) of
%%         ok ->
%%             receive_body(Conn, StreamId, <<>>);
%%         {ok, BufferedChunks} ->
%%             Body = process_chunks(BufferedChunks),
%%             receive_body(Conn, StreamId, Body)
%%     end.
%% '''
%% @end
-spec set_stream_handler(conn(), stream_id(), pid()) ->
    ok | {ok, [{binary(), boolean()}]} | {error, term()}.
set_stream_handler(Conn, StreamId, HandlerPid) ->
    quic_h3_connection:set_stream_handler(Conn, StreamId, HandlerPid).

%% @doc Register a handler with options.
%%
%% Options:
%% <ul>
%%   <li>`drain_buffer' - If true (default), returns buffered data.
%%       If false, sends buffered data as messages.</li>
%% </ul>
%% @end
-spec set_stream_handler(conn(), stream_id(), pid(), map()) ->
    ok | {ok, [{binary(), boolean()}]} | {error, term()}.
set_stream_handler(Conn, StreamId, HandlerPid, Opts) ->
    quic_h3_connection:set_stream_handler(Conn, StreamId, HandlerPid, Opts).

%% @doc Unregister a stream handler.
%%
%% Future data will be sent to the connection owner.
%% @end
-spec unset_stream_handler(conn(), stream_id()) -> ok.
unset_stream_handler(Conn, StreamId) ->
    quic_h3_connection:unset_stream_handler(Conn, StreamId).

%%====================================================================
%% Server API
%%====================================================================

%% @doc Start an HTTP/3 server.
%%
%% The server listens on the given port and accepts HTTP/3 connections.
%% Each incoming request triggers the handler with request details.
%%
%% The handler can be:
%% <ul>
%%   <li>A function: `fun(Conn, StreamId, Method, Path, Headers) -> ok'</li>
%%   <li>A module implementing `handle_request/5'</li>
%% </ul>
%%
%% Example:
%% ```
%% {ok, _} = quic_h3:start_server(my_server, 4433, #{
%%%     cert => CertDer,
%%%     key => KeyTerm,
%%%     handler => fun(Conn, StreamId, <<"GET">>, Path, _) ->
%%%         Body = <<"Hello from ", Path/binary>>,
%%%         quic_h3:send_response(Conn, StreamId, 200, []),
%%%         quic_h3:send_data(Conn, StreamId, Body, true)
%%%     end
%%% }).
%%% '''
%%% @end
-spec start_server(Name, Port, Opts) -> {ok, pid()} | {error, term()} when
    Name :: atom(),
    Port :: inet:port_number(),
    Opts :: server_opts().
start_server(Name, Port, Opts) ->
    Handler = maps:get(handler, Opts, fun default_handler/5),
    H3Settings = maps:get(settings, Opts, #{}),
    StreamTypeHandler = maps:get(stream_type_handler, Opts, undefined),
    H3DatagramEnabled = maps:get(h3_datagram_enabled, Opts, false),
    PerConn = maps:get(connection_handler, Opts, undefined),
    QuicOpts0 = build_server_quic_opts(Opts),
    Listener = self(),
    ListenerDefaults = #{
        handler => Handler,
        settings => H3Settings,
        stream_type_handler => StreamTypeHandler,
        h3_datagram_enabled => H3DatagramEnabled,
        owner => Listener
    },
    QuicOpts = QuicOpts0#{
        connection_handler => fun(ConnPid, _ConnRef) ->
            h3_connection_handler(
                ConnPid, resolve_per_conn_opts(ListenerDefaults, PerConn, ConnPid)
            )
        end
    },
    quic:start_server(Name, Port, QuicOpts).

%% Merge per-connection overrides (returned by the caller-supplied
%% connection_handler fun) over the listener defaults. Keeps the
%% no-hook behaviour identical to the listener-wide setup.
resolve_per_conn_opts(Defaults, undefined, _ConnPid) ->
    Defaults;
resolve_per_conn_opts(Defaults, Fun, ConnPid) when is_function(Fun, 1) ->
    Overrides = Fun(ConnPid),
    true = is_map(Overrides),
    maps:merge(Defaults, Overrides).

%% @doc Stop an HTTP/3 server.
-spec stop_server(atom()) -> ok | {error, term()}.
stop_server(Name) ->
    quic:stop_server(Name).

%% @doc Send an HTTP response (server only).
%%
%% Sends the response status and headers. The body should be
%% sent separately using `send_data/4'.
%% @end
-spec send_response(conn(), stream_id(), status(), headers()) ->
    ok | {error, term()}.
send_response(Conn, StreamId, Status, Headers) ->
    quic_h3_connection:send_response(Conn, StreamId, Status, Headers).

%%====================================================================
%% Server Push API (RFC 9114 Section 4.6)
%%====================================================================

%% @doc Initiate a server push (server only).
%%
%% Sends a PUSH_PROMISE on the request stream and allocates a push ID.
%% Returns the push ID for subsequent send_push_response/send_push_data calls.
%%
%% The Headers should contain the pseudo-headers for the pushed request:
%% `:method', `:scheme', `:authority', and `:path'.
%% @end
-spec push(conn(), stream_id(), headers()) -> {ok, push_id()} | {error, term()}.
push(Conn, RequestStreamId, Headers) ->
    quic_h3_connection:push(Conn, RequestStreamId, Headers).

%% @doc Send response headers on a push stream (server only).
%%
%% After push/3 returns a push ID, use this to send the response headers.
%% The `:status' pseudo-header is added automatically.
%% @end
-spec send_push_response(conn(), push_id(), status(), headers()) -> ok | {error, term()}.
send_push_response(Conn, PushId, Status, Headers) ->
    quic_h3_connection:send_push_response(Conn, PushId, Status, Headers).

%% @doc Send data on a push stream (server only).
%%
%% Set Fin to true to indicate this is the last data.
%% @end
-spec send_push_data(conn(), push_id(), binary(), boolean()) -> ok | {error, term()}.
send_push_data(Conn, PushId, Data, Fin) ->
    quic_h3_connection:send_push_data(Conn, PushId, Data, Fin).

%%====================================================================
%% Client Push API
%%====================================================================

%% @doc Set the maximum push ID (client only).
%%
%% This enables server push up to the specified push ID.
%% Call this after connecting to allow the server to push resources.
%% The MaxPushId cannot be decreased once set.
%%
%% Example:
%% ```
%% %% Enable push with up to 10 promised resources (push IDs 0-9)
%% ok = quic_h3:set_max_push_id(Conn, 9).
%% '''
%% @end
-spec set_max_push_id(conn(), push_id()) -> ok | {error, term()}.
set_max_push_id(Conn, MaxPushId) ->
    quic_h3_connection:set_max_push_id(Conn, MaxPushId).

%% @doc Cancel a push (client only).
%%
%% Sends CANCEL_PUSH to tell the server we don't want this push.
%% Can be called after receiving a push_promise notification.
%% @end
-spec cancel_push(conn(), push_id()) -> ok.
cancel_push(Conn, PushId) ->
    quic_h3_connection:cancel_push(Conn, PushId).

%%====================================================================
%% HTTP Datagrams (RFC 9297)
%%====================================================================

%% @doc Send an HTTP Datagram bound to a request stream.
%%
%% Enabled by passing `h3_datagram_enabled => true' to
%% {@link connect/3} or {@link start_server/3}; the underlying QUIC
%% connection must also advertise a non-zero `max_datagram_frame_size'
%% (RFC 9221) for the H3 extension to go live.
%%
%% Returns `{error, h3_datagrams_disabled}' when the extension was not
%% negotiated, `{error, unknown_stream}' when the stream id is not a
%% known request stream, or one of the RFC 9221 error atoms
%% (`datagrams_not_supported', `datagram_too_large',
%% `datagram_too_large_for_path', `congestion_limited') forwarded from
%% the QUIC layer.
%%
%% Payload for a WebTransport-style CONNECT session is typically handed
%% over unmodified; the quarter-stream-id prefix is added automatically.
%% @end
-spec send_datagram(conn(), stream_id(), iodata()) -> ok | {error, term()}.
send_datagram(Conn, StreamId, Data) ->
    quic_h3_connection:send_datagram(Conn, StreamId, Data).

%% @doc Whether both sides negotiated RFC 9297 support and the
%% extension is live on this connection.
-spec h3_datagrams_enabled(conn()) -> boolean().
h3_datagrams_enabled(Conn) ->
    quic_h3_connection:h3_datagrams_enabled(Conn).

%% @doc Max payload we can fit in one H3 DATAGRAM for the given stream.
%% Returns 0 if RFC 9297 isn't live or the peer advertised 0 for
%% `max_datagram_frame_size'.
-spec max_datagram_size(conn(), stream_id()) -> non_neg_integer().
max_datagram_size(Conn, StreamId) ->
    quic_h3_connection:max_datagram_size(Conn, StreamId).

%%====================================================================
%% Query API
%%====================================================================

%% @doc Get local HTTP/3 settings.
-spec get_settings(conn()) -> map().
get_settings(Conn) ->
    quic_h3_connection:get_settings(Conn).

%% @doc Get peer HTTP/3 settings.
%%
%% Returns `undefined' if SETTINGS has not been received yet.
%% @end
-spec get_peer_settings(conn()) -> map() | undefined.
get_peer_settings(Conn) ->
    quic_h3_connection:get_peer_settings(Conn).

%% @doc Get the underlying QUIC connection for an H3 connection.
%%
%% Needed for WebTransport which uses native QUIC streams alongside H3.
%% @end
-spec get_quic_conn(conn()) -> pid().
get_quic_conn(Conn) ->
    quic_h3_connection:get_quic_conn(Conn).

%% @doc Wait for H3 connection to be ready.
%%
%% Blocks until the connection is established and SETTINGS exchanged,
%% or until the timeout expires.
%% @end
-spec wait_connected(conn(), timeout()) -> ok | {error, timeout}.
wait_connected(Conn, Timeout) ->
    receive
        {quic_h3, Conn, connected} -> ok
    after Timeout ->
        {error, timeout}
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

to_binary(Host) when is_binary(Host) ->
    Host;
to_binary(Host) when is_list(Host) ->
    list_to_binary(Host);
to_binary({A, B, C, D}) when is_integer(A), is_integer(B), is_integer(C), is_integer(D) ->
    list_to_binary(inet:ntoa({A, B, C, D}));
to_binary({A, B, C, D, E, F, G, H}) when
    is_integer(A),
    is_integer(B),
    is_integer(C),
    is_integer(D),
    is_integer(E),
    is_integer(F),
    is_integer(G),
    is_integer(H)
->
    list_to_binary(inet:ntoa({A, B, C, D, E, F, G, H})).

build_client_quic_opts(Host, Opts) ->
    BaseOpts = #{
        alpn => [<<"h3">>],
        server_name => Host
    },
    %% Add TLS options
    TlsOpts = maps:with([cert, key, cacerts, verify], Opts),
    %% Add any custom QUIC options
    QuicOpts = maps:get(quic_opts, Opts, #{}),
    Merged = maps:merge(maps:merge(BaseOpts, TlsOpts), QuicOpts),
    maybe_enable_quic_datagrams(Opts, Merged).

build_server_quic_opts(Opts) ->
    BaseOpts = #{
        alpn => [<<"h3">>]
    },
    %% TLS options (required for server)
    TlsOpts = maps:with([cert, key, cacerts], Opts),
    %% Custom QUIC options
    QuicOpts = maps:get(quic_opts, Opts, #{}),
    Merged = maps:merge(maps:merge(BaseOpts, TlsOpts), QuicOpts),
    maybe_enable_quic_datagrams(Opts, Merged).

%% When the caller opts into H3 datagrams but hasn't explicitly set
%% max_datagram_frame_size, default it to 65535 so the QUIC layer
%% advertises support. An explicit caller value is respected.
maybe_enable_quic_datagrams(Opts, QuicOpts) ->
    case maps:get(h3_datagram_enabled, Opts, false) of
        true ->
            case maps:is_key(max_datagram_frame_size, QuicOpts) of
                true -> QuicOpts;
                false -> QuicOpts#{max_datagram_frame_size => 65535}
            end;
        false ->
            QuicOpts
    end.

%% @private
%% Connection handler callback for QUIC server.
%% Called when a new QUIC connection is established (before handshake completes).
%% `Opts' carries the per-server configuration captured in start_server/3:
%% `handler', `settings', `stream_type_handler', `h3_datagram_enabled',
%% and the calling process pid as `owner' (used when any extension hook
%% needs owner-delivered messages).
h3_connection_handler(QuicConnPid, #{handler := Handler, settings := Settings} = Opts) ->
    StreamTypeHandler = maps:get(stream_type_handler, Opts, undefined),
    H3DatagramEnabled = maps:get(h3_datagram_enabled, Opts, false),
    Owner = maps:get(owner, Opts, self()),
    H3Opts = build_h3_opts(Settings, Handler, StreamTypeHandler, H3DatagramEnabled),
    %% When an extension hook is active, owner-addressed events need to
    %% reach the caller of start_server/3 rather than this transient
    %% callback process.
    OwnerForH3 =
        case (StreamTypeHandler =/= undefined) orelse H3DatagramEnabled of
            true -> Owner;
            false -> self()
        end,
    case
        gen_statem:start_link(
            quic_h3_connection, {server, QuicConnPid, H3Opts, OwnerForH3}, []
        )
    of
        {ok, H3Conn} ->
            %% Transfer ownership to H3 process so it receives QUIC events
            %% including the {connected, Info} notification after handshake completes
            ok = quic:set_owner_sync(QuicConnPid, H3Conn),
            {ok, H3Conn};
        {error, Reason} ->
            {error, Reason}
    end.

build_h3_opts(Settings, Handler, undefined, false) ->
    #{settings => Settings, handler => Handler};
build_h3_opts(Settings, Handler, StreamTypeHandler, H3DatagramEnabled) ->
    Base = #{settings => Settings, handler => Handler},
    Base1 =
        case StreamTypeHandler of
            undefined -> Base;
            _ -> Base#{stream_type_handler => StreamTypeHandler}
        end,
    Base1#{h3_datagram_enabled => H3DatagramEnabled}.

default_handler(Conn, StreamId, _Method, _Path, _Headers) ->
    send_response(Conn, StreamId, 404, [{<<"content-type">>, <<"text/plain">>}]),
    send_data(Conn, StreamId, <<"Not Found">>, true).
