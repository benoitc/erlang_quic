%%% -*- erlang -*-
%%%
%%% The server acknowledges the client's Initial in the packet that
%%% carries its ServerHello.
%%%
%%% An acknowledgement in an Initial of its own comes after the
%%% Handshake flight. When that flight has used up the amplification
%%% budget it is never sent, and the client gets no RTT sample: its PTO
%%% stays at the 1 s default and it probes too rarely to repair a lost
%%% flight before its handshake timeout (go-x-net in the interop
%%% runner's amplificationlimit test).

-module(quic_server_initial_ack_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([server_hello_carries_the_ack/1]).

-define(CONNECT_MS, 15000).

suite() ->
    [{timetrap, {minutes, 1}}].

all() ->
    [server_hello_carries_the_ack].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

server_hello_carries_the_ack(_Config) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        Conn = connect_recording(maps:get(port, Server)),
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?CONNECT_MS -> ct:fail("connect timeout")
        end,
        ClientInitial =
            receive
                {client_datagram, C} -> C
            after 0 -> ct:fail("no client datagram")
            end,
        ServerFirst =
            receive
                {server_datagram, S} -> S
            after 0 -> ct:fail("no server datagram")
            end,
        Frames = initial_frames(dcid(ClientInitial), ServerFirst),
        ct:pal("server's first Initial: ~p", [[element(1, F) || F <- Frames, is_tuple(F)]]),
        ?assert(lists:any(fun(F) -> is_tuple(F) andalso element(1, F) =:= crypto end, Frames)),
        ?assert(lists:any(fun(F) -> is_tuple(F) andalso element(1, F) =:= ack end, Frames)),
        quic:close(Conn, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

dcid(<<1:1, 1:1, _:6, _Version:32, DL, DCID:DL/binary, _/binary>>) ->
    DCID.

initial_frames(OrigDCID, <<1:1, 1:1, 0:2, _:4, _/binary>> = Datagram) ->
    <<_:5/binary, DL, _:DL/binary, SL, _:SL/binary, Rest0/binary>> = Datagram,
    {TokenLen, Rest1} = quic_varint:decode(Rest0),
    <<_:TokenLen/binary, Rest2/binary>> = Rest1,
    {Len, Rest3} = quic_varint:decode(Rest2),
    <<Encrypted:Len/binary, _/binary>> = Rest3,
    Header = binary:part(Datagram, 0, byte_size(Datagram) - byte_size(Rest3)),
    {Key, IV, HP} = quic_keys:derive_initial_server(OrigDCID),
    {ok, _PN, _, Plaintext} =
        quic_aead:unprotect_long_packet(aes_128_gcm, Key, IV, HP, Header, Encrypted, undefined),
    {ok, Frames} = quic_frame:decode_all(Plaintext),
    Frames.

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
            Self ! {client_datagram, iolist_to_binary(Pkt)},
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
