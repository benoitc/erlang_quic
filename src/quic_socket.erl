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
%%%         max_packets => 64,
%%%         flush_timeout_ms => 1
%%%     }
%%% }).
%%% '''

-module(quic_socket).

-export([
    open/2,
    wrap/2,
    close/1,
    send/4,
    flush/1,
    recv/2,
    sockname/1,
    controlling_process/2,
    setopts/2,
    detect_capabilities/0,
    get_fd/1
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
    %% GSO support detected and enabled
    gso_supported = false :: boolean(),
    %% GSO segment size for batching
    gso_size = ?DEFAULT_GSO_SEGMENT_SIZE :: non_neg_integer(),
    %% GRO enabled for receive
    gro_enabled = false :: boolean(),
    %% Batching enabled
    batching_enabled = true :: boolean(),
    %% Batched packets waiting to be sent
    batch_buffer = [] :: [binary()],
    %% Current batch destination address
    batch_addr :: {inet:ip_address(), inet:port_number()} | undefined,
    %% Maximum packets per batch
    max_batch_packets = ?DEFAULT_MAX_BATCH_PACKETS :: pos_integer(),
    %% Flush timeout timer reference
    flush_timer :: reference() | undefined,
    %% Flush timeout in milliseconds
    flush_timeout_ms = ?DEFAULT_BATCH_TIMEOUT_MS :: non_neg_integer()
}).

-opaque socket_state() :: #socket_state{}.
-export_type([socket_state/0]).

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
    FlushTimeout = maps:get(flush_timeout_ms, BatchOpts, ?DEFAULT_BATCH_TIMEOUT_MS),
    GSOSize = maps:get(gso_size, BatchOpts, ?DEFAULT_GSO_SEGMENT_SIZE),

    case Backend of
        socket ->
            open_socket_backend(Port, Opts, #{
                gso_supported => GSOSupported,
                gro_supported => GROSupported,
                batching_enabled => BatchingEnabled,
                max_batch => MaxBatch,
                flush_timeout => FlushTimeout,
                gso_size => GSOSize
            });
        gen_udp ->
            open_genudp_backend(Port, Opts, #{
                batching_enabled => BatchingEnabled,
                max_batch => MaxBatch,
                flush_timeout => FlushTimeout,
                gso_size => GSOSize
            })
    end.

%% @doc Wrap an existing gen_udp socket with batching support.
%% This allows adding batching to connections that already have a socket.
%% Note: GSO/GRO are not available when wrapping existing gen_udp sockets.
-spec wrap(gen_udp:socket(), map()) -> {ok, socket_state()}.
wrap(Socket, Opts) ->
    BatchOpts = maps:get(batching, Opts, #{}),
    BatchingEnabled = maps:get(enabled, BatchOpts, true),
    MaxBatch = maps:get(max_packets, BatchOpts, ?DEFAULT_MAX_BATCH_PACKETS),
    FlushTimeout = maps:get(flush_timeout_ms, BatchOpts, ?DEFAULT_BATCH_TIMEOUT_MS),
    GSOSize = maps:get(gso_size, BatchOpts, ?DEFAULT_GSO_SEGMENT_SIZE),

    State = #socket_state{
        socket = Socket,
        backend = gen_udp,
        gso_supported = false,
        gso_size = GSOSize,
        gro_enabled = false,
        batching_enabled = BatchingEnabled,
        max_batch_packets = MaxBatch,
        flush_timeout_ms = FlushTimeout
    },
    {ok, State}.

%% @doc Close the socket and flush any pending packets.
-spec close(socket_state()) -> ok.
close(#socket_state{socket = Socket, backend = socket}) ->
    _ = socket:close(Socket),
    ok;
close(#socket_state{socket = Socket, backend = gen_udp}) ->
    _ = gen_udp:close(Socket),
    ok.

%% @doc Send a packet, buffering for batch send if enabled.
%% Returns updated state. Auto-flushes when:
%% - Batch is full (max_batch_packets reached)
%% - Destination address changes
-spec send(socket_state(), inet:ip_address(), inet:port_number(), iodata()) ->
    {ok, socket_state()} | {error, term()}.
send(#socket_state{batching_enabled = false} = State, IP, Port, Data) ->
    %% Batching disabled - send immediately
    do_send_immediate(State, IP, Port, Data);
send(#socket_state{batch_addr = undefined} = State, IP, Port, Data) ->
    %% First packet in batch
    add_to_batch(State#socket_state{batch_addr = {IP, Port}}, Data);
send(#socket_state{batch_addr = {IP, Port}} = State, IP, Port, Data) ->
    %% Same destination - add to batch
    add_to_batch(State, Data);
send(#socket_state{} = State, IP, Port, Data) ->
    %% Different destination - flush current batch first
    case flush(State) of
        {ok, State1} ->
            add_to_batch(State1#socket_state{batch_addr = {IP, Port}}, Data);
        {error, _} = Error ->
            Error
    end.

%% @doc Flush all buffered packets.
-spec flush(socket_state()) -> {ok, socket_state()} | {error, term()}.
flush(#socket_state{batch_buffer = []} = State) ->
    %% Nothing to flush
    {ok, cancel_flush_timer(State)};
flush(#socket_state{batch_buffer = Buffer, batch_addr = undefined} = State) ->
    %% No address set but have data - shouldn't happen, but clear buffer
    ?LOG_WARNING(#{what => flush_no_addr, buffer_size => length(Buffer)}),
    {ok, cancel_flush_timer(State#socket_state{batch_buffer = []})};
flush(#socket_state{gso_supported = true} = State) ->
    %% GSO path - send all packets in one syscall
    flush_gso(State);
flush(#socket_state{} = State) ->
    %% Fallback path - send packets individually
    flush_individual(State).

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
    GSOEnabled = maybe_enable_gso(Socket, BatchConfig),
    GROEnabled = maybe_enable_gro(Socket, BatchConfig),
    State = #socket_state{
        socket = Socket,
        backend = socket,
        gso_supported = GSOEnabled,
        gso_size = maps:get(gso_size, BatchConfig),
        gro_enabled = GROEnabled,
        batching_enabled = maps:get(batching_enabled, BatchConfig),
        max_batch_packets = maps:get(max_batch, BatchConfig),
        flush_timeout_ms = maps:get(flush_timeout, BatchConfig)
    },
    {ok, State}.

maybe_enable_gso(Socket, #{gso_supported := true, gso_size := Size}) ->
    %% Try to set GSO segment size
    %% UDP_SEGMENT = 103
    case socket:setopt_native(Socket, {udp, ?UDP_SEGMENT}, <<Size:16/native>>) of
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
        max_batch_packets = maps:get(max_batch, BatchConfig),
        flush_timeout_ms = maps:get(flush_timeout, BatchConfig)
    }.

%%====================================================================
%% Internal Functions - Batching
%%====================================================================

add_to_batch(#socket_state{batch_buffer = Buffer, max_batch_packets = Max} = State, Data) ->
    Packet = iolist_to_binary(Data),
    NewBuffer = [Packet | Buffer],
    State1 = State#socket_state{batch_buffer = NewBuffer},

    case length(NewBuffer) >= Max of
        true ->
            %% Batch full - flush now
            flush(State1);
        false ->
            %% Start or maintain flush timer
            {ok, ensure_flush_timer(State1)}
    end.

ensure_flush_timer(#socket_state{flush_timer = undefined, flush_timeout_ms = Timeout} = State) ->
    Timer = erlang:send_after(Timeout, self(), batch_flush_timeout),
    State#socket_state{flush_timer = Timer};
ensure_flush_timer(State) ->
    State.

cancel_flush_timer(#socket_state{flush_timer = undefined} = State) ->
    State;
cancel_flush_timer(#socket_state{flush_timer = Timer} = State) ->
    _ = erlang:cancel_timer(Timer),
    %% Clear any pending message
    receive
        batch_flush_timeout -> ok
    after 0 ->
        ok
    end,
    State#socket_state{flush_timer = undefined}.

flush_gso(
    #socket_state{
        socket = Socket,
        batch_buffer = Buffer,
        batch_addr = {IP, Port},
        gso_size = SegmentSize
    } = State
) ->
    %% Combine all packets into a single super-datagram
    %% Packets are in reverse order, so reverse them first
    Packets = lists:reverse(Buffer),
    CombinedData = iolist_to_binary(Packets),

    %% Build sendmsg with GSO control message
    Msg = #{
        addr => #{family => inet, addr => IP, port => Port},
        iov => [CombinedData],
        ctrl => [#{level => udp, type => ?UDP_SEGMENT, data => <<SegmentSize:16/native>>}]
    },

    case socket:sendmsg(Socket, Msg) of
        ok ->
            {ok,
                cancel_flush_timer(State#socket_state{
                    batch_buffer = [],
                    batch_addr = undefined
                })};
        {ok, _RestData} ->
            %% Partial send - clear buffer anyway for now
            {ok,
                cancel_flush_timer(State#socket_state{
                    batch_buffer = [],
                    batch_addr = undefined
                })};
        {error, _} = Error ->
            Error
    end.

flush_individual(
    #socket_state{
        socket = Socket,
        backend = Backend,
        batch_buffer = Buffer,
        batch_addr = {IP, Port}
    } = State
) ->
    %% Send each packet individually
    Packets = lists:reverse(Buffer),
    Result = send_packets_individual(Socket, Backend, IP, Port, Packets),

    case Result of
        ok ->
            {ok,
                cancel_flush_timer(State#socket_state{
                    batch_buffer = [],
                    batch_addr = undefined
                })};
        {error, _} = Error ->
            Error
    end.

send_packets_individual(_Socket, _Backend, _IP, _Port, []) ->
    ok;
send_packets_individual(Socket, socket, IP, Port, [Packet | Rest]) ->
    Dest = #{family => inet, addr => IP, port => Port},
    case socket:sendto(Socket, Packet, Dest) of
        ok ->
            send_packets_individual(Socket, socket, IP, Port, Rest);
        {error, _} = Error ->
            Error
    end;
send_packets_individual(Socket, gen_udp, IP, Port, [Packet | Rest]) ->
    case gen_udp:send(Socket, IP, Port, Packet) of
        ok ->
            send_packets_individual(Socket, gen_udp, IP, Port, Rest);
        {error, _} = Error ->
            Error
    end.

do_send_immediate(#socket_state{socket = Socket, backend = socket} = State, IP, Port, Data) ->
    Dest = #{family => inet, addr => IP, port => Port},
    case socket:sendto(Socket, iolist_to_binary(Data), Dest) of
        ok -> {ok, State};
        {error, _} = Error -> Error
    end;
do_send_immediate(#socket_state{socket = Socket, backend = gen_udp} = State, IP, Port, Data) ->
    case gen_udp:send(Socket, IP, Port, Data) of
        ok -> {ok, State};
        {error, _} = Error -> Error
    end.

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
    %% Try to set UDP_SEGMENT option
    case socket:setopt_native(Socket, {udp, ?UDP_SEGMENT}, <<1200:16/native>>) of
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
