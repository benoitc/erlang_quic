%%% -*- erlang -*-
%%%
%%% QUIC Socket Abstraction with UDP Packet Batching
%%% Supports GSO/GRO on Linux (OTP 27+), gen_udp fallback elsewhere
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc UDP socket abstraction with packet batching support.
%%%
%%% This module provides a unified socket interface that:
%%% - Uses the OTP 27+ `socket' module with GSO/GRO on Linux
%%% - Falls back to gen_udp on macOS/Windows/other platforms
%%% - Batches outgoing packets for improved throughput
%%% - Handles coalesced packets on receive (GRO)
%%%
%%% == Architecture ==
%%% ```
%%% quic_connection/quic_listener
%%%         |
%%%    quic_socket (this module)
%%%         |
%%%   socket module (OTP 27+) with GSO/GRO on Linux
%%%         or
%%%   gen_udp fallback on macOS/Windows
%%% '''
%%%
%%% == Configuration ==
%%% ```
%%% quic:start_server(Name, Port, #{
%%%     batching => #{
%%%         enabled => true,
%%%         max_packets => 64
%%%     }
%%% }).
%%% '''

-module(quic_socket).

-export([
    open/2,
    open_for_send/2,
    open_server_send/2,
    wrap/2,
    new_sender/2,
    close/1,
    send/4,
    send_immediate/4,
    flush/1,
    recv/2,
    sockname/1,
    controlling_process/2,
    setopts/2,
    detect_capabilities/0,
    get_fd/1,
    get_socket/1,
    gso_supported/1,
    info/1,
    start_client_receiver/2,
    stop_client_receiver/1,
    set_socket/2
]).

-include("quic.hrl").
-include_lib("kernel/include/logger.hrl").

%% GSO/GRO socket option constants for Linux
%% UDP_SEGMENT = 103 (for GSO)
%% UDP_GRO = 104 (for GRO)
-define(UDP_SEGMENT, 103).
-define(UDP_GRO, 104).

-record(socket_state, {
    %% The underlying socket
    socket :: socket:socket() | gen_udp:socket(),
    %% Which backend we're using
    backend :: socket | gen_udp,
    %% Whether this socket_state owns the socket (true = close on cleanup)
    %% When wrapping an existing socket, this is false to avoid closing caller's socket
    owns_socket = true :: boolean(),
    %% GSO support detected and enabled
    gso_supported = false :: boolean(),
    %% GSO segment size for batching
    gso_size = ?DEFAULT_GSO_SEGMENT_SIZE :: non_neg_integer(),
    %% GRO enabled for receive
    gro_enabled = false :: boolean(),
    %% Batching enabled
    batching_enabled = true :: boolean(),
    %% Batched packets waiting to be sent (stored as packet_view())
    batch_buffer = [] :: [packet_view()],
    %% Number of packets in batch (avoids O(n) length/1)
    batch_count = 0 :: non_neg_integer(),
    %% Current batch destination address
    batch_addr :: {inet:ip_address(), inet:port_number()} | undefined,
    %% Maximum packets per batch
    max_batch_packets = ?DEFAULT_MAX_BATCH_PACKETS :: pos_integer(),
    %% Observability counters: bumped on successful flush only. Skip
    %% immediate (unbatched) sends so packets_coalesced strictly measures
    %% the batching win. batch_flushes counts each flush that actually
    %% transmitted something.
    batch_flushes = 0 :: non_neg_integer(),
    packets_coalesced = 0 :: non_neg_integer()
}).

%% Packet can be:
%%   - binary() - already flat
%%   - {iov, [binary()]} - explicit iov parts (preferred for zero-copy)
%%   - iodata() - any iolist (for backwards compatibility)
-type packet_view() :: binary() | {iov, [binary()]} | iodata().

-opaque socket_state() :: #socket_state{}.
-export_type([socket_state/0, packet_view/0]).

%%====================================================================
%% API
%%====================================================================

%% @doc Open a UDP socket with batching support.
%% Options:
%%   - All standard gen_udp options
%%   - batching => #{enabled => true, max_packets => 64, flush_timeout_ms => 1}
-spec open(inet:port_number(), map()) ->
    {ok, socket_state()} | {error, term()}.
open(Port, Opts) ->
    Capabilities = detect_capabilities(),
    Backend = maps:get(backend, Capabilities, gen_udp),
    GSOSupported = maps:get(gso, Capabilities, false),
    GROSupported = maps:get(gro, Capabilities, false),

    BatchOpts = maps:get(batching, Opts, #{}),
    BatchingEnabled = maps:get(enabled, BatchOpts, true),
    MaxBatch = maps:get(max_packets, BatchOpts, ?DEFAULT_MAX_BATCH_PACKETS),
    GSOSize = maps:get(gso_size, BatchOpts, ?DEFAULT_GSO_SEGMENT_SIZE),

    case Backend of
        socket ->
            open_socket_backend(Port, Opts, #{
                gso_supported => GSOSupported,
                gro_supported => GROSupported,
                batching_enabled => BatchingEnabled,
                max_batch => MaxBatch,
                gso_size => GSOSize
            });
        gen_udp ->
            open_genudp_backend(Port, Opts, #{
                batching_enabled => BatchingEnabled,
                max_batch => MaxBatch,
                gso_size => GSOSize
            })
    end.

%% @doc Open a UDP socket optimized for sending (client connections).
%% Detects platform capabilities and enables GSO if available.
%% Unlike open/2, this is optimized for a single destination.
-spec open_for_send(inet:ip_address(), map()) ->
    {ok, socket_state()} | {error, term()}.
open_for_send(RemoteIP, Opts) ->
    Capabilities = detect_capabilities(),
    %% Allow the caller to force a backend (via `backend => socket'
    %% in Opts) so the opt-in client path can request the OTP socket
    %% NIF even on platforms where capability detection would pick
    %% `gen_udp' by default. Similarly `gso => false' lets the caller
    %% opt out of GSO even when the platform supports it — the opt-in
    %% client path uses that to avoid UDP_SEGMENT until the batched
    %% send path is validated against gen_udp servers.
    DetectedBackend = maps:get(backend, Capabilities, gen_udp),
    Backend = maps:get(backend, Opts, DetectedBackend),
    DetectedGSO = maps:get(gso, Capabilities, false),
    GSOSupported = maps:get(gso, Opts, DetectedGSO),

    BatchOpts = maps:get(batching, Opts, #{}),
    BatchingEnabled = maps:get(enabled, BatchOpts, true),
    MaxBatch = maps:get(max_packets, BatchOpts, ?DEFAULT_MAX_BATCH_PACKETS),
    GSOSize = maps:get(gso_size, BatchOpts, ?DEFAULT_GSO_SEGMENT_SIZE),

    case Backend of
        socket ->
            open_send_socket_backend(RemoteIP, Opts, #{
                gso_supported => GSOSupported,
                batching_enabled => BatchingEnabled,
                max_batch => MaxBatch,
                gso_size => GSOSize
            });
        gen_udp ->
            open_send_genudp_backend(RemoteIP, Opts, #{
                batching_enabled => BatchingEnabled,
                max_batch => MaxBatch,
                gso_size => GSOSize
            })
    end.

%% @doc Open a server send socket bound to a local address with reuseport.
%% Uses OTP socket backend with GSO support on Linux for high throughput.
%% This is for server connections that need to send from a specific local port.
-spec open_server_send({inet:ip_address(), inet:port_number()}, map()) ->
    {ok, socket_state()} | {error, term()}.
open_server_send({LocalIP, LocalPort}, Opts) ->
    Capabilities = detect_capabilities(),
    Backend = maps:get(backend, Capabilities, gen_udp),
    GSOSupported = maps:get(gso, Capabilities, false),

    BatchOpts = maps:get(batching, Opts, #{}),
    BatchingEnabled = maps:get(enabled, BatchOpts, true),
    MaxBatch = maps:get(max_packets, BatchOpts, ?DEFAULT_MAX_BATCH_PACKETS),
    GSOSize = maps:get(gso_size, BatchOpts, ?DEFAULT_GSO_SEGMENT_SIZE),

    BatchConfig = #{
        gso_supported => GSOSupported,
        batching_enabled => BatchingEnabled,
        max_batch => MaxBatch,
        gso_size => GSOSize
    },

    case Backend of
        socket ->
            open_server_send_socket(LocalIP, LocalPort, Opts, BatchConfig);
        gen_udp ->
            open_server_send_genudp(LocalIP, LocalPort, Opts, BatchConfig)
    end.

%% Open OTP socket for server send with reuseport binding
open_server_send_socket(LocalIP, LocalPort, Opts, BatchConfig) ->
    Family = family(LocalIP),
    case socket:open(Family, dgram, udp) of
        {ok, Socket} ->
            configure_server_send_socket(Socket, LocalIP, LocalPort, Family, Opts, BatchConfig);
        {error, _} = Error ->
            Error
    end.

configure_server_send_socket(Socket, LocalIP, LocalPort, Family, Opts, BatchConfig) ->
    %% Set reuseaddr for binding to same port as listener.
    %% NOTE: Do NOT use reuseport here! With reuseport, the kernel distributes
    %% incoming packets between all sockets bound to the port. Since this socket
    %% is only for sending (nobody reads from it), any packets directed here would
    %% be dropped, causing the listener to miss incoming data.
    ok = socket:setopt(Socket, {socket, reuseaddr}, true),
    set_socket_buffer_sizes(Socket, Opts),

    %% Bind to local address
    SockAddr = #{family => Family, addr => LocalIP, port => LocalPort},
    case socket:bind(Socket, SockAddr) of
        ok ->
            GSOEnabled = maybe_enable_gso(Socket, BatchConfig),
            State = #socket_state{
                socket = Socket,
                backend = socket,
                owns_socket = true,
                gso_supported = GSOEnabled,
                gso_size = maps:get(gso_size, BatchConfig),
                gro_enabled = false,
                batching_enabled = maps:get(batching_enabled, BatchConfig),
                max_batch_packets = maps:get(max_batch, BatchConfig)
            },
            {ok, State};
        {error, _} = Error ->
            socket:close(Socket),
            Error
    end.

%% Fallback to gen_udp for server send (non-Linux platforms)
%% NOTE: Do NOT use reuseport here! With reuseport, the kernel distributes
%% incoming packets between all sockets bound to the port. Since this socket
%% is only for sending, any packets directed here would be dropped.
open_server_send_genudp(LocalIP, LocalPort, Opts, BatchConfig) ->
    RecBuf = maps:get(recbuf, Opts, ?DEFAULT_UDP_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_UDP_SNDBUF),
    SocketOpts =
        [
            binary,
            {ip, LocalIP},
            {active, false},
            {reuseaddr, true},
            {recbuf, RecBuf},
            {sndbuf, SndBuf}
        ],
    case gen_udp:open(LocalPort, SocketOpts) of
        {ok, Socket} ->
            {ok, build_genudp_state(Socket, BatchConfig)};
        {error, _} = Error ->
            Error
    end.

%% @doc Get the underlying socket from a socket_state.
-spec get_socket(socket_state()) -> socket:socket() | gen_udp:socket().
get_socket(#socket_state{socket = Socket}) ->
    Socket.

%% @doc Swap the underlying socket handle without rebuilding the
%% `#socket_state{}'. Used by client-migration rebind so batching
%% configuration is preserved while the handle points at a fresh
%% ephemeral port. Callers must flush any pending batch before
%% swapping; packets buffered under the old handle cannot migrate to
%% the new one.
-spec set_socket(socket_state(), gen_udp:socket() | socket:socket()) -> socket_state().
set_socket(#socket_state{} = State, NewSocket) ->
    State#socket_state{socket = NewSocket}.

%% @doc Check if GSO is supported for this socket_state.
-spec gso_supported(socket_state()) -> boolean().
gso_supported(#socket_state{gso_supported = Supported}) ->
    Supported.

%% @doc Return a map describing the socket_state's configuration and
%% observability counters. Intended for debugging, benchmarking, and
%% test assertions.
-spec info(socket_state()) ->
    #{
        backend := gen_udp | socket,
        gso_supported := boolean(),
        gso_size := non_neg_integer(),
        gro_enabled := boolean(),
        batching_enabled := boolean(),
        max_batch_packets := pos_integer(),
        batch_flushes := non_neg_integer(),
        packets_coalesced := non_neg_integer()
    }.
info(#socket_state{
    backend = Backend,
    gso_supported = GSO,
    gso_size = GSOSize,
    gro_enabled = GRO,
    batching_enabled = Batching,
    max_batch_packets = MaxBatch,
    batch_flushes = Flushes,
    packets_coalesced = Coalesced
}) ->
    #{
        backend => Backend,
        gso_supported => GSO,
        gso_size => GSOSize,
        gro_enabled => GRO,
        batching_enabled => Batching,
        max_batch_packets => MaxBatch,
        batch_flushes => Flushes,
        packets_coalesced => Coalesced
    }.

%% @doc Wrap an existing gen_udp socket with batching support.
%% This allows adding batching to connections that already have a socket.
%% Note: GSO/GRO are not available when wrapping existing gen_udp sockets.
%% The wrapped socket is NOT owned by this state - close/1 will not close it.
-spec wrap(gen_udp:socket(), map()) -> {ok, socket_state()}.
wrap(Socket, Opts) ->
    BatchOpts = maps:get(batching, Opts, #{}),
    BatchingEnabled = maps:get(enabled, BatchOpts, true),
    MaxBatch = maps:get(max_packets, BatchOpts, ?DEFAULT_MAX_BATCH_PACKETS),
    GSOSize = maps:get(gso_size, BatchOpts, ?DEFAULT_GSO_SEGMENT_SIZE),

    State = #socket_state{
        socket = Socket,
        backend = gen_udp,
        owns_socket = false,
        gso_supported = false,
        gso_size = GSOSize,
        gro_enabled = false,
        batching_enabled = BatchingEnabled,
        max_batch_packets = MaxBatch
    },
    {ok, State}.

%% @doc Create a fresh per-connection sender that reuses an existing
%% socket (e.g. the listener's shared UDP socket on the server side).
%% Each caller gets its own batch buffer so multiple connections can
%% accumulate packets independently before flush. GSO is inherited from
%% the underlying backend when requested.
%% The socket is NOT owned by the returned state - close/1 will not close it.
-spec new_sender(gen_udp:socket() | socket:socket(), map()) ->
    {ok, socket_state()}.
new_sender(Socket, Opts) ->
    Backend = maps:get(backend, Opts, gen_udp),
    GSOSupported = maps:get(gso_supported, Opts, false),
    BatchOpts = maps:get(batching, Opts, #{}),
    BatchingEnabled = maps:get(enabled, BatchOpts, true),
    MaxBatch = maps:get(max_packets, BatchOpts, ?DEFAULT_MAX_BATCH_PACKETS),
    GSOSize = maps:get(gso_size, BatchOpts, ?DEFAULT_GSO_SEGMENT_SIZE),

    State = #socket_state{
        socket = Socket,
        backend = Backend,
        owns_socket = false,
        gso_supported = GSOSupported andalso (Backend =:= socket),
        gso_size = GSOSize,
        gro_enabled = false,
        batching_enabled = BatchingEnabled,
        max_batch_packets = MaxBatch
    },
    {ok, State}.

%% @doc Close the socket and flush any pending packets.
%% Only closes the socket if owns_socket is true (i.e., socket was created by us).
-spec close(socket_state()) -> ok.
close(#socket_state{owns_socket = false}) ->
    %% Don't close wrapped sockets - caller owns them
    ok;
close(#socket_state{socket = Socket, backend = socket}) ->
    _ = socket:close(Socket),
    ok;
close(#socket_state{socket = Socket, backend = gen_udp}) ->
    _ = gen_udp:close(Socket),
    ok.

%% @doc Send a packet immediately, bypassing the batch buffer.
%% Intended for one-shot control-plane sends (version negotiation,
%% retry, stateless reset) where batching adds no value and persisting
%% the returned state is awkward.
-spec send_immediate(socket_state(), inet:ip_address(), inet:port_number(), packet_view()) ->
    {ok, socket_state()} | {error, term()}.
send_immediate(State, IP, Port, Packet) ->
    do_send_immediate(State, IP, Port, Packet).

%% @doc Send a packet, buffering for batch send if enabled.
%% Packet can be:
%%   - binary() - already flat packet
%%   - {iov, [binary()]} - packet parts for scatter/gather (avoids copy)
%%
%% Returns updated state. Auto-flushes when:
%% - Batch is full (max_batch_packets reached)
%% - Destination address changes
-spec send(socket_state(), inet:ip_address(), inet:port_number(), packet_view()) ->
    {ok, socket_state()} | {error, term()}.
send(#socket_state{batching_enabled = false} = State, IP, Port, Packet) ->
    %% Batching disabled - send immediately
    do_send_immediate(State, IP, Port, Packet);
send(#socket_state{batch_addr = undefined} = State, IP, Port, Packet) ->
    %% First packet in batch
    add_to_batch(State#socket_state{batch_addr = {IP, Port}}, Packet);
send(#socket_state{batch_addr = {IP, Port}} = State, IP, Port, Packet) ->
    %% Same destination - add to batch
    add_to_batch(State, Packet);
send(#socket_state{} = State, IP, Port, Packet) ->
    %% Different destination - flush current batch first
    case flush(State) of
        {ok, State1} ->
            add_to_batch(State1#socket_state{batch_addr = {IP, Port}}, Packet);
        {error, _} = Error ->
            Error
    end.

%% @doc Flush all buffered packets.
-spec flush(socket_state()) -> {ok, socket_state()} | {error, term()}.
flush(#socket_state{batch_count = 0} = State) ->
    %% Nothing to flush
    {ok, State};
flush(#socket_state{batch_count = Count, batch_addr = undefined} = State) ->
    %% No address set but have data - shouldn't happen, but clear buffer
    ?LOG_WARNING(#{what => flush_no_addr, buffer_size => Count}),
    {ok, clear_batch(State)};
flush(#socket_state{gso_supported = true, batch_count = 1} = State) ->
    %% Single-packet batch has no segmentation work; direct send.
    flush_individual(State);
flush(#socket_state{gso_supported = true, batch_buffer = Buffer, gso_size = GSO} = State) ->
    %% UDP_SEGMENT requires every segment except the last to be
    %% exactly gso_size. Handshake flights coalesce Initial-padded-to-
    %% 1200 with a ~400 byte Handshake packet; a naive GSO split
    %% mis-aligns those boundaries and the client cannot decode. When
    %% the batch is not uniform, fall through to individual sends.
    case gso_batch_uniform(Buffer, GSO) of
        true -> flush_gso(State);
        false -> flush_individual(State)
    end;
flush(#socket_state{} = State) ->
    %% Fallback path - send packets individually
    flush_individual(State).

%% Batch buffer is stored newest-first (head was last added). For GSO
%% correctness we need all packets EXCEPT the last-transmitted one
%% (which is the head of the buffer) to be exactly gso_size. The
%% last-transmitted packet may be shorter.
gso_batch_uniform([], _GSO) ->
    true;
gso_batch_uniform([_Last | Earlier], GSO) ->
    lists:all(fun(P) -> iolist_size(P) =:= GSO end, Earlier).

%% @doc Receive packets from the socket.
%% On Linux with GRO, may return multiple coalesced packets.
-spec recv(socket_state(), timeout()) ->
    {ok, {inet:ip_address(), inet:port_number()}, [binary()]} | {error, term()}.
recv(#socket_state{socket = Socket, backend = socket, gro_enabled = true}, Timeout) ->
    %% GRO path - receive potentially coalesced packets
    recv_gro(Socket, Timeout);
recv(#socket_state{socket = Socket, backend = socket}, Timeout) ->
    %% Socket backend without GRO
    case socket:recvfrom(Socket, 0, [], Timeout) of
        {ok, {#{addr := IP, port := Port}, Data}} ->
            {ok, {IP, Port}, [Data]};
        {error, _} = Error ->
            Error
    end;
recv(#socket_state{socket = Socket, backend = gen_udp}, Timeout) ->
    %% gen_udp backend
    receive
        {udp, Socket, IP, Port, Data} ->
            {ok, {IP, Port}, [Data]}
    after Timeout ->
        {error, timeout}
    end.

%% @doc Get the local address and port.
-spec sockname(socket_state()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
sockname(#socket_state{socket = Socket, backend = socket}) ->
    case socket:sockname(Socket) of
        {ok, #{addr := IP, port := Port}} ->
            {ok, {IP, Port}};
        {error, _} = Error ->
            Error
    end;
sockname(#socket_state{socket = Socket, backend = gen_udp}) ->
    inet:sockname(Socket).

%% @doc Set the controlling process.
-spec controlling_process(socket_state(), pid()) -> ok | {error, term()}.
controlling_process(#socket_state{socket = Socket, backend = gen_udp}, Pid) ->
    gen_udp:controlling_process(Socket, Pid);
controlling_process(#socket_state{backend = socket}, _Pid) ->
    %% socket module doesn't have controlling_process concept
    ok.

%% @doc Set socket options.
-spec setopts(socket_state(), list()) -> ok | {error, term()}.
setopts(#socket_state{socket = Socket, backend = gen_udp}, Opts) ->
    inet:setopts(Socket, Opts);
setopts(#socket_state{socket = Socket, backend = socket}, Opts) ->
    %% Convert gen_udp style opts to socket module
    set_socket_opts(Socket, Opts).

%% @doc Get the underlying file descriptor.
-spec get_fd(socket_state()) -> {ok, integer()} | {error, term()}.
get_fd(#socket_state{socket = Socket, backend = gen_udp}) ->
    case inet:getfd(Socket) of
        {ok, Fd} -> {ok, Fd};
        Error -> Error
    end;
get_fd(#socket_state{socket = Socket, backend = socket}) ->
    %% socket module - get native fd
    try
        Fd = socket:info(Socket),
        case maps:get(fd, Fd, undefined) of
            undefined -> {error, no_fd};
            FdVal -> {ok, FdVal}
        end
    catch
        _:_ -> {error, not_supported}
    end.

%% @doc Spawn a client-side receiver process for the `socket' backend.
%%
%% The OTP `socket' module does not support `{active, N}' semantics,
%% so instead we spawn a dedicated process that loops on
%% `socket:recvfrom/4' and forwards each datagram as
%% `{udp, Owner, IP, Port, Data}' to the owning connection process.
%% This lets the existing `quic_connection' receive path keep
%% pattern-matching on the gen_udp-style message shape without
%% any branching.
%%
%% Returns the receiver pid, linked to the caller so it terminates
%% when the connection process exits.
-spec start_client_receiver(socket_state(), pid()) -> {ok, pid()} | {error, term()}.
start_client_receiver(#socket_state{backend = socket} = SocketState, Owner) when is_pid(Owner) ->
    Pid = spawn_link(fun() -> client_recv_loop(SocketState, Owner) end),
    {ok, Pid};
start_client_receiver(#socket_state{backend = gen_udp}, _Owner) ->
    {error, not_supported_on_gen_udp}.

%% @doc Stop a client receiver process previously returned by
%% `start_client_receiver/2'. Safe to call with `undefined'.
-spec stop_client_receiver(pid() | undefined) -> ok.
stop_client_receiver(undefined) ->
    ok;
stop_client_receiver(Pid) when is_pid(Pid) ->
    case is_process_alive(Pid) of
        true ->
            unlink(Pid),
            exit(Pid, shutdown),
            ok;
        false ->
            ok
    end.

%% Blocking recvfrom loop. Forwards each datagram as a gen_udp-shaped
%% `{udp, Socket, IP, Port, Data}' tuple so the owner's existing
%% receive handlers work unchanged — `Socket' here matches the OTP
%% socket handle stored in `#state.socket'. Uses a 100ms timeout so
%% exit signals from the linked owner are processed promptly rather
%% than blocking forever in the NIF.
client_recv_loop(#socket_state{socket = Socket} = SocketState, Owner) ->
    case socket:recvfrom(Socket, 0, [], 100) of
        {ok, {#{addr := IP, port := Port}, Data}} ->
            Owner ! {udp, Socket, IP, Port, Data},
            client_recv_loop(SocketState, Owner);
        {error, timeout} ->
            client_recv_loop(SocketState, Owner);
        {error, closed} ->
            ok;
        {error, _Reason} ->
            client_recv_loop(SocketState, Owner)
    end.

%% @doc Detect platform capabilities for GSO/GRO.
-spec detect_capabilities() -> map().
detect_capabilities() ->
    case os:type() of
        {unix, linux} ->
            detect_linux_capabilities();
        _ ->
            #{gso => false, gro => false, backend => gen_udp}
    end.

%%====================================================================
%% Internal Functions - Socket Backend
%%====================================================================

open_socket_backend(Port, Opts, BatchConfig) ->
    case socket:open(inet, dgram, udp) of
        {ok, Socket} ->
            configure_and_bind_socket(Socket, Port, Opts, BatchConfig);
        {error, _} = Error ->
            Error
    end.

configure_and_bind_socket(Socket, Port, Opts, BatchConfig) ->
    ok = socket:setopt(Socket, {socket, reuseaddr}, true),
    set_socket_buffer_sizes(Socket, Opts),
    maybe_set_reuseport(Socket, Opts),
    bind_and_finalize_socket(Socket, Port, BatchConfig).

set_socket_buffer_sizes(Socket, Opts) ->
    RecBuf = maps:get(recbuf, Opts, ?DEFAULT_UDP_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_UDP_SNDBUF),
    _ = socket:setopt(Socket, {socket, rcvbuf}, RecBuf),
    _ = socket:setopt(Socket, {socket, sndbuf}, SndBuf),
    ok.

maybe_set_reuseport(Socket, Opts) ->
    case maps:get(reuseport, Opts, false) of
        true -> _ = socket:setopt(Socket, {socket, reuseport}, true);
        false -> ok
    end.

bind_and_finalize_socket(Socket, Port, BatchConfig) ->
    Addr = #{family => inet, addr => any, port => Port},
    case socket:bind(Socket, Addr) of
        ok ->
            build_socket_state(Socket, BatchConfig);
        {error, _} = Error ->
            socket:close(Socket),
            Error
    end.

build_socket_state(Socket, BatchConfig) ->
    %% GSO is applied per-message via the UDP_SEGMENT cmsg in
    %% flush_gso/1, never as a socket-level setsockopt. A socket-level
    %% UDP_SEGMENT would force GSO segmentation on every outbound
    %% datagram including the short handshake packets and fallback
    %% sends, which stalled the handshake on ubuntu-24.04.
    GSOEnabled = maps:get(gso_supported, BatchConfig, false),
    GROEnabled = maybe_enable_gro(Socket, BatchConfig),
    State = #socket_state{
        socket = Socket,
        backend = socket,
        gso_supported = GSOEnabled,
        gso_size = maps:get(gso_size, BatchConfig),
        gro_enabled = GROEnabled,
        batching_enabled = maps:get(batching_enabled, BatchConfig),
        max_batch_packets = maps:get(max_batch, BatchConfig)
    },
    {ok, State}.

%% Retained for open_server_send's separate-socket path, which still
%% uses a dedicated socket where a socket-level UDP_SEGMENT is safe
%% (it is a send-only socket, never used for short handshake packets).
maybe_enable_gso(Socket, #{gso_supported := true, gso_size := Size}) ->
    case socket:setopt_native(Socket, {udp, ?UDP_SEGMENT}, <<Size:32/native>>) of
        ok -> true;
        {error, _} -> false
    end;
maybe_enable_gso(_, _) ->
    false.

maybe_enable_gro(Socket, #{gro_supported := true}) ->
    %% Try to enable GRO
    %% UDP_GRO = 104
    case socket:setopt_native(Socket, {udp, ?UDP_GRO}, <<1:32/native>>) of
        ok -> true;
        {error, _} -> false
    end;
maybe_enable_gro(_, _) ->
    false.

%%====================================================================
%% Internal Functions - Send-optimized Socket (for client connections)
%%====================================================================

%% Open socket backend optimized for sending (no binding to specific port)
open_send_socket_backend(RemoteIP, Opts, BatchConfig) ->
    Family = family(RemoteIP),
    case socket:open(Family, dgram, udp) of
        {ok, Socket} ->
            configure_send_socket(Socket, Opts, BatchConfig);
        {error, _} = Error ->
            Error
    end.

configure_send_socket(Socket, Opts, BatchConfig) ->
    ok = socket:setopt(Socket, {socket, reuseaddr}, true),
    set_socket_buffer_sizes(Socket, Opts),
    %% GSO is applied per-message via the UDP_SEGMENT cmsg in
    %% flush_gso/1, never as a socket-level setsockopt. A socket-level
    %% UDP_SEGMENT would force GSO segmentation on every outbound
    %% datagram, including short handshake packets and non-uniform
    %% fallback sends, which stalled handshakes and mis-segmented
    %% coalesced Initial+Handshake flights against gen_udp servers.
    GSOEnabled = maps:get(gso_supported, BatchConfig, false),
    State = #socket_state{
        socket = Socket,
        backend = socket,
        owns_socket = true,
        gso_supported = GSOEnabled,
        gso_size = maps:get(gso_size, BatchConfig),
        gro_enabled = false,
        batching_enabled = maps:get(batching_enabled, BatchConfig),
        max_batch_packets = maps:get(max_batch, BatchConfig)
    },
    {ok, State}.

%% Open gen_udp backend optimized for sending (ephemeral port)
open_send_genudp_backend(_RemoteIP, Opts, BatchConfig) ->
    SocketOpts = build_send_genudp_opts(Opts),
    case gen_udp:open(0, SocketOpts) of
        {ok, Socket} ->
            {ok, build_genudp_state(Socket, BatchConfig)};
        {error, _} = Error ->
            Error
    end.

build_send_genudp_opts(Opts) ->
    ActiveN = maps:get(active_n, Opts, 100),
    ExtraFlags = maps:get(extra_socket_opts, Opts, []),
    RecBuf = maps:get(recbuf, Opts, ?DEFAULT_UDP_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_UDP_SNDBUF),
    [
        binary,
        inet,
        {active, ActiveN},
        {reuseaddr, true},
        {recbuf, RecBuf},
        {sndbuf, SndBuf}
    ] ++ ExtraFlags.

%%====================================================================
%% Internal Functions - gen_udp Backend
%%====================================================================

open_genudp_backend(Port, Opts, BatchConfig) ->
    SocketOpts = build_genudp_opts(Opts),
    case gen_udp:open(Port, SocketOpts) of
        {ok, Socket} ->
            {ok, build_genudp_state(Socket, BatchConfig)};
        {error, _} = Error ->
            Error
    end.

build_genudp_opts(Opts) ->
    ActiveN = maps:get(active_n, Opts, 100),
    ReusePort = maps:get(reuseport, Opts, false),
    ExtraFlags = maps:get(extra_socket_opts, Opts, []),
    RecBuf = maps:get(recbuf, Opts, ?DEFAULT_UDP_RECBUF),
    SndBuf = maps:get(sndbuf, Opts, ?DEFAULT_UDP_SNDBUF),
    BaseOpts = [
        binary,
        inet,
        {active, ActiveN},
        {reuseaddr, true},
        {recbuf, RecBuf},
        {sndbuf, SndBuf}
    ],
    ReuseOpts =
        case ReusePort of
            true -> [{reuseport, true}, {reuseport_lb, true}];
            false -> []
        end,
    BaseOpts ++ ReuseOpts ++ ExtraFlags.

build_genudp_state(Socket, BatchConfig) ->
    #socket_state{
        socket = Socket,
        backend = gen_udp,
        gso_supported = false,
        gso_size = maps:get(gso_size, BatchConfig),
        gro_enabled = false,
        batching_enabled = maps:get(batching_enabled, BatchConfig),
        max_batch_packets = maps:get(max_batch, BatchConfig)
    }.

%%====================================================================
%% Internal Functions - Batching
%%====================================================================

add_to_batch(
    #socket_state{batch_buffer = Buffer, batch_count = Count, max_batch_packets = Max} = State,
    Packet
) ->
    %% Store packet as-is (binary or {iov, Parts}) - no flattening yet
    NewBuffer = [Packet | Buffer],
    NewCount = Count + 1,
    State1 = State#socket_state{batch_buffer = NewBuffer, batch_count = NewCount},

    case NewCount >= Max of
        true ->
            %% Batch full - flush now
            flush(State1);
        false ->
            %% Just accumulate - caller flushes at send cycle boundaries
            {ok, State1}
    end.

flush_gso(
    #socket_state{
        socket = Socket,
        batch_buffer = Buffer,
        batch_addr = {IP, Port},
        gso_size = SegmentSize
    } = State
) ->
    %% Pass the batch as a multi-iov to socket:sendmsg/2. The kernel
    %% treats concatenated iov buffers as a single logical payload and
    %% segments at SegmentSize byte boundaries via the UDP_SEGMENT
    %% cmsg, so the wire bytes are identical to the old flatten-first
    %% shape. We save a full user-space copy per flush (up to ~76 KB
    %% at a 64-packet batch of 1200-byte segments).
    Packets = lists:reverse(Buffer),
    PacketIov = [normalize_packet(P) || P <- Packets],
    Msg = #{
        addr => #{family => family(IP), addr => IP, port => Port},
        iov => PacketIov,
        ctrl => [#{level => udp, type => ?UDP_SEGMENT, data => <<SegmentSize:16/native>>}]
    },

    case socket:sendmsg(Socket, Msg) of
        ok ->
            {ok, record_flush(State)};
        {ok, RestData} ->
            %% Partial send - GSO didn't send all data.
            TotalBytes = iolist_size(PacketIov),
            Remaining = iolist_size(RestData),
            ?LOG_WARNING(#{
                what => gso_partial_send,
                sent => TotalBytes - Remaining,
                remaining => Remaining
            }),
            %% Disable GSO and retry remaining data individually. The
            %% retry path accounts for the coalesced packets itself, so
            %% clear batch state here without bumping counters.
            State1 = clear_batch(State#socket_state{gso_supported = false}),
            send_remaining_individually(State1, IP, Port, RestData);
        {error, _} = Error ->
            Error
    end.

flush_individual(#socket_state{backend = socket} = State) ->
    flush_individual_socket(State);
flush_individual(#socket_state{backend = gen_udp} = State) ->
    flush_individual_genudp(State).

flush_individual_socket(
    #socket_state{
        socket = Socket,
        batch_buffer = Buffer,
        batch_addr = {IP, Port}
    } = State
) ->
    %% Send each packet using sendmsg with iov (no flattening)
    Packets = lists:reverse(Buffer),
    Dest = #{family => family(IP), addr => IP, port => Port},
    case send_packets_socket(Socket, Dest, Packets, 0) of
        {ok, _Sent} ->
            {ok, record_flush(State)};
        {error, Reason, _Sent} ->
            {error, Reason}
    end.

flush_individual_genudp(
    #socket_state{
        socket = Socket,
        batch_buffer = Buffer,
        batch_addr = {IP, Port}
    } = State
) ->
    %% Send each packet using gen_udp (must flatten)
    Packets = lists:reverse(Buffer),
    case send_packets_genudp(Socket, IP, Port, Packets, 0) of
        {ok, _Sent} ->
            {ok, record_flush(State)};
        {error, Reason, _Sent} ->
            {error, Reason}
    end.

%% Send packets using socket:sendmsg with iov (no flattening for socket backend)
send_packets_socket(_Socket, _Dest, [], Sent) ->
    {ok, Sent};
send_packets_socket(Socket, Dest, [Packet | Rest], Sent) ->
    Msg = #{
        addr => Dest,
        iov => packet_iov(Packet)
    },
    case socket:sendmsg(Socket, Msg) of
        ok ->
            send_packets_socket(Socket, Dest, Rest, Sent + 1);
        {ok, _Remaining} ->
            {error, partial_send, Sent};
        {error, Reason} ->
            {error, Reason, Sent}
    end.

%% Send packets using gen_udp (must flatten to binary)
send_packets_genudp(_Socket, _IP, _Port, [], Sent) ->
    {ok, Sent};
send_packets_genudp(Socket, IP, Port, [Packet | Rest], Sent) ->
    Bin = normalize_packet(Packet),
    case gen_udp:send(Socket, IP, Port, Bin) of
        ok ->
            send_packets_genudp(Socket, IP, Port, Rest, Sent + 1);
        {error, Reason} ->
            {error, Reason, Sent}
    end.

%% Send remaining data after GSO partial write (RestData is iolist)
%% Split into segment-sized packets to preserve QUIC datagram boundaries
send_remaining_individually(
    #socket_state{socket = Socket, gso_size = SegmentSize} = State, IP, Port, RestData
) ->
    Dest = #{family => family(IP), addr => IP, port => Port},
    Data = iolist_to_binary(RestData),
    Packets = split_into_segments(Data, SegmentSize),
    send_segments(Socket, Dest, Packets, State).

%% Split binary data into segment-sized chunks
split_into_segments(Data, SegmentSize) ->
    split_into_segments(Data, SegmentSize, []).

split_into_segments(<<>>, _SegmentSize, Acc) ->
    lists:reverse(Acc);
split_into_segments(Data, SegmentSize, Acc) when byte_size(Data) =< SegmentSize ->
    lists:reverse([Data | Acc]);
split_into_segments(Data, SegmentSize, Acc) ->
    <<Segment:SegmentSize/binary, Rest/binary>> = Data,
    split_into_segments(Rest, SegmentSize, [Segment | Acc]).

%% Send each segment as a separate datagram
send_segments(_Socket, _Dest, [], State) ->
    {ok, State};
send_segments(Socket, Dest, [Packet | Rest], State) ->
    case socket:sendto(Socket, Packet, Dest) of
        ok -> send_segments(Socket, Dest, Rest, State);
        {error, _} = Error -> Error
    end.

do_send_immediate(#socket_state{socket = Socket, backend = socket} = State, IP, Port, Packet) ->
    %% Use sendmsg with iov - no flattening needed
    Msg = #{
        addr => #{family => family(IP), addr => IP, port => Port},
        iov => packet_iov(Packet)
    },
    case socket:sendmsg(Socket, Msg) of
        ok -> {ok, State};
        {ok, _Remaining} -> {error, partial_send};
        {error, Reason} -> {error, Reason}
    end;
do_send_immediate(#socket_state{socket = Socket, backend = gen_udp} = State, IP, Port, Packet) ->
    %% gen_udp needs flat binary
    Bin = normalize_packet(Packet),
    case gen_udp:send(Socket, IP, Port, Bin) of
        ok -> {ok, State};
        {error, _} = Error -> Error
    end.

%%====================================================================
%% Internal Functions - Packet View Helpers
%%====================================================================

%% Convert packet_view to iov list for sendmsg
%% {iov, Parts} uses parts directly (zero-copy path)
%% binary is wrapped in list
%% iodata is flattened to list of binaries (preserves binary boundaries)
packet_iov(Bin) when is_binary(Bin) ->
    [Bin];
packet_iov({iov, Parts}) ->
    Parts;
packet_iov(IoData) when is_list(IoData) ->
    %% Flatten iolist to list of binaries (preserves binary boundaries)
    flatten_iodata(IoData, []).

%% Flatten iodata to list of binaries (for iov)
%% Preserves binary boundaries, concatenates byte sequences
flatten_iodata([], Acc) ->
    lists:reverse(Acc);
flatten_iodata([H | T], Acc) when is_binary(H) ->
    flatten_iodata(T, [H | Acc]);
flatten_iodata([H | T], Acc) when is_list(H) ->
    %% Nested list - recurse
    flatten_iodata(T, flatten_iodata(H, Acc));
flatten_iodata([H | T], Acc) when is_integer(H), H >= 0, H =< 255 ->
    %% Byte value - collect consecutive bytes into a binary
    {Bytes, Rest} = collect_bytes([H | T], []),
    flatten_iodata(Rest, [list_to_binary(Bytes) | Acc]).

%% Collect consecutive byte integers
collect_bytes([H | T], Acc) when is_integer(H), H >= 0, H =< 255 ->
    collect_bytes(T, [H | Acc]);
collect_bytes(Rest, Acc) ->
    {lists:reverse(Acc), Rest}.

%% Flatten packet_view to binary (for GSO and gen_udp)
normalize_packet(Bin) when is_binary(Bin) ->
    Bin;
normalize_packet({iov, Parts}) ->
    iolist_to_binary(Parts);
normalize_packet(IoData) when is_list(IoData) ->
    iolist_to_binary(IoData).

%% Clear batch state without bumping observability counters. Used by
%% error / partial-send paths where we do not want to count as a
%% successful flush.
clear_batch(State) ->
    State#socket_state{
        batch_buffer = [],
        batch_count = 0,
        batch_addr = undefined
    }.

%% Record a successful flush and clear the batch state. Increments
%% batch_flushes by one and packets_coalesced by the number of packets
%% that were coalesced before the send. Use this only when the send
%% actually transmitted the full batch.
record_flush(
    #socket_state{
        batch_count = Count,
        batch_flushes = Flushes,
        packets_coalesced = Coalesced
    } = State
) ->
    State#socket_state{
        batch_buffer = [],
        batch_count = 0,
        batch_addr = undefined,
        batch_flushes = Flushes + 1,
        packets_coalesced = Coalesced + Count
    }.

%% Get address family
family({_, _, _, _}) -> inet;
family({_, _, _, _, _, _, _, _}) -> inet6.

%%====================================================================
%% Internal Functions - GRO Receive
%%====================================================================

recv_gro(Socket, Timeout) ->
    %% Receive with GRO - may get coalesced packets
    case socket:recvmsg(Socket, 0, 128, [], Timeout) of
        {ok, #{addr := #{addr := IP, port := Port}, iov := [Data], ctrl := Ctrl}} ->
            %% Check for GRO segment size in control messages
            case extract_gro_segment_size(Ctrl) of
                undefined ->
                    %% No GRO - single packet
                    {ok, {IP, Port}, [Data]};
                SegmentSize ->
                    %% Split coalesced data into individual packets
                    Packets = split_gro_packets(Data, SegmentSize),
                    {ok, {IP, Port}, Packets}
            end;
        {ok, #{addr := #{addr := IP, port := Port}, iov := [Data]}} ->
            %% No control messages
            {ok, {IP, Port}, [Data]};
        {error, _} = Error ->
            Error
    end.

extract_gro_segment_size([]) ->
    undefined;
extract_gro_segment_size([#{level := udp, type := ?UDP_GRO, data := <<Size:16/native>>} | _]) ->
    Size;
extract_gro_segment_size([_ | Rest]) ->
    extract_gro_segment_size(Rest).

split_gro_packets(Data, SegmentSize) ->
    split_gro_packets(Data, SegmentSize, []).

split_gro_packets(<<>>, _SegmentSize, Acc) ->
    lists:reverse(Acc);
split_gro_packets(Data, SegmentSize, Acc) when byte_size(Data) =< SegmentSize ->
    lists:reverse([Data | Acc]);
split_gro_packets(Data, SegmentSize, Acc) ->
    <<Packet:SegmentSize/binary, Rest/binary>> = Data,
    split_gro_packets(Rest, SegmentSize, [Packet | Acc]).

%%====================================================================
%% Internal Functions - Linux Capability Detection
%%====================================================================

detect_linux_capabilities() ->
    %% Check OTP version - need 27+ for socket module features
    case otp_version_check() of
        false ->
            #{gso => false, gro => false, backend => gen_udp};
        true ->
            %% Try to create a test socket and check GSO/GRO
            test_linux_socket_capabilities()
    end.

otp_version_check() ->
    %% Check if OTP version is 27 or higher
    try
        OtpRelease = erlang:system_info(otp_release),
        Version = list_to_integer(OtpRelease),
        Version >= 27
    catch
        _:_ -> false
    end.

test_linux_socket_capabilities() ->
    case socket:open(inet, dgram, udp) of
        {ok, Socket} ->
            %% Test GSO
            GSOSupported = test_gso(Socket),
            %% Test GRO
            GROSupported = test_gro(Socket),

            socket:close(Socket),

            #{
                gso => GSOSupported,
                gro => GROSupported,
                backend => socket
            };
        {error, _} ->
            #{gso => false, gro => false, backend => gen_udp}
    end.

test_gso(Socket) ->
    %% UDP_SEGMENT setsockopt expects sizeof(int) on Linux; passing 2
    %% bytes makes the kernel reject with EINVAL and GSO is reported as
    %% unsupported even on kernels that have it.
    case socket:setopt_native(Socket, {udp, ?UDP_SEGMENT}, <<1200:32/native>>) of
        ok -> true;
        {error, _} -> false
    end.

test_gro(Socket) ->
    %% Try to set UDP_GRO option
    case socket:setopt_native(Socket, {udp, ?UDP_GRO}, <<1:32/native>>) of
        ok -> true;
        {error, _} -> false
    end.

%%====================================================================
%% Internal Functions - Socket Option Conversion
%%====================================================================

set_socket_opts(_Socket, []) ->
    ok;
set_socket_opts(Socket, [{active, N} | Rest]) when is_integer(N) ->
    %% socket module doesn't have active mode - skip
    set_socket_opts(Socket, Rest);
set_socket_opts(Socket, [{active, _} | Rest]) ->
    %% Skip active mode
    set_socket_opts(Socket, Rest);
set_socket_opts(Socket, [{recbuf, Size} | Rest]) ->
    _ = socket:setopt(Socket, {socket, rcvbuf}, Size),
    set_socket_opts(Socket, Rest);
set_socket_opts(Socket, [{sndbuf, Size} | Rest]) ->
    _ = socket:setopt(Socket, {socket, sndbuf}, Size),
    set_socket_opts(Socket, Rest);
set_socket_opts(Socket, [_ | Rest]) ->
    %% Skip unknown options
    set_socket_opts(Socket, Rest).
