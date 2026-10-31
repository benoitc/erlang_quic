%%% -*- erlang -*-
%%%
%%% The server's first flight shares datagrams.
%%%
%%% Until the client's address is validated every datagram counts three
%%% times against what the client has sent. A ServerHello Initial padded
%%% to 1200 bytes with the Handshake flight in datagrams of its own left
%%% room for two copies of the flight; a client that loses both and does
%%% not probe again (xquic) deadlocks the handshake.

-module(quic_coalesced_flight_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([initial_and_handshake_share_a_datagram/1]).

-define(CONNECT_MS, 15000).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [initial_and_handshake_share_a_datagram].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

initial_and_handshake_share_a_datagram(_Config) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Conn = connect_recording(maps:get(port, Server)),
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?CONNECT_MS -> ct:fail("connect timeout")
        end,
        Datagrams = recorded(),
        Shapes = [{quic_test_bridge:levels(D), byte_size(D)} || D <- Datagrams],
        ct:pal("server datagrams before connected: ~p", [Shapes]),
        [First | _] = [S || {Levels, _} = S <- Shapes, lists:member(handshake, Levels)],
        ?assertMatch({[initial, handshake | _], Size} when Size >= 1200, First),
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

connect_recording(Port) ->
    Self = self(),
    SocketRef = make_ref(),
    Bridge = quic_test_bridge:start(#{
        server => {{127, 0, 0, 1}, Port},
        socket_ref => SocketRef,
        drop_in => fun(Pkt, _N) ->
            Self ! {server_datagram, Pkt},
            false
        end
    }),
    Adapter = #{
        send_fun => fun(IP, P, Pkt) ->
            Bridge ! {send, IP, P, Pkt},
            ok
        end,
        close_fun => fun() -> quic_test_bridge:stop(Bridge) end,
        local => {{127, 0, 0, 1}, 0},
        socket_ref => SocketRef
    },
    Opts = #{
        verify => false,
        alpn => [<<"echo">>],
        socket_backend => adapter,
        socket_adapter => Adapter
    },
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
    ok = quic_test_bridge:set_conn(Bridge, Conn),
    Conn.

recorded() ->
    receive
        {server_datagram, D} -> [D | recorded()]
    after 0 -> []
    end.
