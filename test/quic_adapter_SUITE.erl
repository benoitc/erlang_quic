%%% -*- erlang -*-
%%%
%%% Tests for the `socket_backend => adapter' option of quic:connect/4.
%%%
%%% The adapter backend lets a caller plug in custom datagram send/recv
%%% callbacks instead of opening a UDP socket. The test bridges the
%%% callbacks to a private gen_udp socket that talks to the in-process
%%% echo server, exercising a full handshake + bidi stream round-trip.

-module(quic_adapter_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    connect_via_adapter/1,
    rejects_missing_adapter/1,
    rejects_bad_adapter/1,
    rejects_socket_with_adapter/1
]).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [
        connect_via_adapter,
        rejects_missing_adapter,
        rejects_bad_adapter,
        rejects_socket_with_adapter
    ].

init_per_suite(Config) ->
    {ok, Echo} = quic_test_echo_server:start(),
    [{echo_server, Echo} | Config].

end_per_suite(Config) ->
    case ?config(echo_server, Config) of
        undefined -> ok;
        Echo -> quic_test_echo_server:stop(Echo)
    end,
    ok.

%%====================================================================
%% Tests
%%====================================================================

connect_via_adapter(Config) ->
    Echo = ?config(echo_server, Config),
    Port = maps:get(port, Echo),
    ServerIP = {127, 0, 0, 1},
    %% Pre-allocate the opaque socket handle so the bridge knows what
    %% reference to put in the `{udp, Ref, ...}' forwards.
    SocketRef = make_ref(),

    Bridge = spawn_link(fun() -> bridge_init(ServerIP, Port, SocketRef) end),

    SendFun =
        fun(IP, P, Pkt) ->
            Bridge ! {send, IP, P, Pkt},
            ok
        end,
    CloseFun = fun() ->
        Bridge ! stop,
        ok
    end,

    Adapter = #{
        send_fun => SendFun,
        close_fun => CloseFun,
        local => {{127, 0, 0, 1}, 0},
        socket_ref => SocketRef
    },

    Opts = (quic_test_echo_server:client_opts())#{
        alpn => [<<"echo">>],
        socket_backend => adapter,
        socket_adapter => Adapter
    },

    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    Bridge ! {set_conn, Conn},

    receive
        {quic, Conn, {connected, _Info}} -> ok
    after 10000 ->
        ct:fail("connect timeout")
    end,

    {ok, StreamId} = quic:open_stream(Conn),
    Payload = <<"hello via adapter">>,
    ok = quic:send_data(Conn, StreamId, Payload, false),

    receive
        {quic, Conn, {stream_data, StreamId, Echoed, _Fin}} ->
            ?assertEqual(Payload, Echoed)
    after 10000 ->
        ct:fail("echo timeout")
    end,

    quic:close(Conn, normal),
    ok.

rejects_missing_adapter(_Config) ->
    Opts = #{socket_backend => adapter},
    ?assertEqual(
        {error, missing_socket_adapter},
        quic:connect(<<"127.0.0.1">>, 12345, Opts, self())
    ).

rejects_bad_adapter(_Config) ->
    Opts = #{socket_backend => adapter, socket_adapter => #{}},
    ?assertEqual(
        {error, badarg_socket_adapter},
        quic:connect(<<"127.0.0.1">>, 12345, Opts, self())
    ).

rejects_socket_with_adapter(_Config) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, false}]),
    try
        Opts = #{
            socket => Sock,
            socket_backend => adapter,
            socket_adapter => #{send_fun => fun(_, _, _) -> ok end}
        },
        ?assertEqual(
            {error, {incompatible_options, [socket, {socket_backend, adapter}]}},
            quic:connect(<<"127.0.0.1">>, 12345, Opts, self())
        )
    after
        gen_udp:close(Sock)
    end.

%%====================================================================
%% Bridge: gen_udp <-> adapter callbacks
%%====================================================================

%% Owns one gen_udp socket and shuttles datagrams between the QUIC
%% client (via the adapter `send_fun' and `{udp, SocketRef, ...}'
%% forwards) and the echo server.
bridge_init(ServerIP, ServerPort, SocketRef) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    bridge_loop(Sock, undefined, ServerIP, ServerPort, SocketRef).

bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef) ->
    receive
        {set_conn, NewConn} ->
            bridge_loop(Sock, NewConn, ServerIP, ServerPort, SocketRef);
        {send, _IP, _Port, Pkt} ->
            ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt),
            bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef);
        {udp, Sock, _IP, _Port, Data} when is_pid(Conn) ->
            Conn ! {udp, SocketRef, ServerIP, ServerPort, Data},
            bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef);
        {udp, Sock, _IP, _Port, _Data} ->
            bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef);
        stop ->
            gen_udp:close(Sock),
            ok;
        _ ->
            bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef)
    end.
