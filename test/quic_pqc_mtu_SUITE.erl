%%% -*- erlang -*-
%%%
%%% Post-quantum Initial-datagram sizing (draft-ietf-tls-ecdhe-mlkem).
%%%
%%% The hybrid X25519MLKEM768 ClientHello is ~1360 bytes and its
%%% ServerHello Initial ~1225 bytes, both past the 1200-byte size that
%%% is safe before PMTU is validated. A single oversized Initial is
%%% dropped on paths with an MTU below ~1470 (IPv6-over-PPPoE 1492,
%%% WireGuard ~1420, mobile ~1400), so the flight must be split across
%%% Initial packets. Loopback has a 16k MTU and hides this, so this
%%% suite watches the bytes on the wire directly via the socket
%%% adapter and asserts every handshake datagram stays within 1200.
%%%
%%% Skipped when the crypto library has no ML-KEM-768 support.

-module(quic_pqc_mtu_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([hybrid_initial_within_1200/1]).

-define(SAFE_INITIAL, 1200).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [hybrid_initial_within_1200].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    case quic_crypto:group_supported(x25519mlkem768) of
        true ->
            {ok, _} = application:ensure_all_started(quic),
            Config;
        false ->
            {skip, "crypto library has no ML-KEM-768 support"}
    end.

end_per_suite(_Config) ->
    ok.

%% Drive a full hybrid handshake with the client behind a socket
%% adapter that records the size and header type of every datagram it
%% sends. Assert: no Initial datagram exceeds 1200 bytes, and the
%% ClientHello actually spans more than one Initial (chunking engaged,
%% not merely a small hello).
hybrid_initial_within_1200(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{groups => [x25519mlkem768, x25519]}),
    try
        Port = maps:get(port, Server),
        ServerIP = {127, 0, 0, 1},
        SocketRef = make_ref(),
        Self = self(),
        Bridge = spawn_link(fun() -> bridge_init(ServerIP, Port, SocketRef, Self) end),

        SendFun = fun(IP, P, Pkt) ->
            Bridge ! {send, IP, P, Pkt},
            ok
        end,
        Adapter = #{
            send_fun => SendFun,
            close_fun => fun() ->
                Bridge ! stop,
                ok
            end,
            local => {{127, 0, 0, 1}, 0},
            socket_ref => SocketRef
        },
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            groups => [x25519mlkem768, x25519],
            socket_backend => adapter,
            socket_adapter => Adapter
        },
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        Bridge ! {set_conn, Conn},
        receive
            {quic, Conn, {connected, _}} -> ok
        after 10000 -> ct:fail("connect timeout")
        end,
        quic:close(Conn, normal),

        Sizes = collect_sizes([]),
        Initials = [Sz || {initial, Sz} <- Sizes],
        Oversized = [Sz || Sz <- Initials, Sz > ?SAFE_INITIAL],
        ct:pal("client Initial datagram sizes: ~p", [Initials]),
        ?assertEqual([], Oversized),
        %% The hybrid ClientHello alone must occupy more than one
        %% Initial datagram: without chunking it would be a single
        %% ~1445-byte datagram and this list would have one big entry.
        ?assert(length(Initials) >= 2)
    after
        quic_test_echo_server:stop(Server)
    end.

%% Drain the size reports the bridge forwarded.
collect_sizes(Acc) ->
    receive
        {dgram, Type, Size} -> collect_sizes([{Type, Size} | Acc])
    after 200 -> lists:reverse(Acc)
    end.

%% Relay between the client adapter and a real UDP socket to the
%% server, reporting each client-egress datagram's size and header
%% type back to the test. QUIC header protection masks only the low 4
%% bits of the first byte for long headers, so the form bit (0x80) and
%% the packet-type bits (0x30) are readable in the clear.
bridge_init(ServerIP, ServerPort, SocketRef, Reporter) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    bridge_loop(Sock, undefined, ServerIP, ServerPort, SocketRef, Reporter).

bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef, Reporter) ->
    receive
        {set_conn, NewConn} ->
            bridge_loop(Sock, NewConn, ServerIP, ServerPort, SocketRef, Reporter);
        {send, _IP, _Port, Pkt} ->
            Reporter ! {dgram, header_type(Pkt), iolist_size(Pkt)},
            ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt),
            bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef, Reporter);
        {udp, Sock, _IP, _Port, Data} when is_pid(Conn) ->
            Conn ! {udp, SocketRef, ServerIP, ServerPort, Data},
            bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef, Reporter);
        stop ->
            gen_udp:close(Sock);
        _ ->
            bridge_loop(Sock, Conn, ServerIP, ServerPort, SocketRef, Reporter)
    end.

header_type(Pkt) ->
    <<First:8, _/binary>> = iolist_to_binary(Pkt),
    case First band 16#80 of
        0 ->
            short;
        _ ->
            case First band 16#30 of
                16#00 -> initial;
                _ -> other_long
            end
    end.
