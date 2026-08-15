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
        Initials = [Sz || {initial, Sz, _Phase} <- Sizes],
        Oversized = [Sz || Sz <- Initials, Sz > ?SAFE_INITIAL],
        ct:pal("client Initial datagram sizes: ~p", [Initials]),
        ?assertEqual([], Oversized),
        %% The ClientHello flight is what the client sends before the
        %% server has answered; later Initials are ACK-only and would
        %% make a plain count of Initials meaningless.
        Hello = [Sz || {initial, Sz, pre_response} <- Sizes],
        ct:pal("ClientHello Initial sizes: ~p", [Hello]),
        %% Chunking engaged: the hybrid ClientHello spans more than one
        %% Initial, and the first chunk is a full one rather than a
        %% truncated hello that happens to fit.
        ?assert(length(Hello) >= 2),
        ?assert(hd(Hello) >= 1100)
    after
        quic_test_echo_server:stop(Server)
    end.

%% Drain the size reports the bridge forwarded.
collect_sizes(Acc) ->
    receive
        {dgram, Type, Size, Phase} -> collect_sizes([{Type, Size, Phase} | Acc])
    after 200 -> lists:reverse(Acc)
    end.

%% Relay between the client adapter and a real UDP socket to the
%% server, reporting each client-egress datagram's size, header type
%% and whether the server had answered yet. QUIC header protection
%% masks only the low 4 bits of the first byte for long headers, so the
%% form bit (0x80) and the packet-type bits (0x30) are readable in the
%% clear.
%%
%% The connection pid only arrives once `quic:connect/4' returns, which
%% is after the ClientHello is on the wire, so datagrams that beat it
%% are buffered rather than dropped.
bridge_init(ServerIP, ServerPort, SocketRef, Reporter) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}]),
    Bridge = #{
        sock => Sock,
        conn => undefined,
        pending => [],
        answered => false,
        server => {ServerIP, ServerPort},
        socket_ref => SocketRef,
        reporter => Reporter
    },
    bridge_loop(Bridge).

bridge_loop(#{sock := Sock, server := {ServerIP, ServerPort}} = Bridge) ->
    receive
        {set_conn, Conn} ->
            Pending = maps:get(pending, Bridge),
            [deliver(Bridge, Conn, Data) || Data <- lists:reverse(Pending)],
            bridge_loop(Bridge#{conn := Conn, pending := []});
        {send, _IP, _Port, Pkt} ->
            Phase =
                case maps:get(answered, Bridge) of
                    true -> post_response;
                    false -> pre_response
                end,
            maps:get(reporter, Bridge) ! {dgram, header_type(Pkt), iolist_size(Pkt), Phase},
            ok = gen_udp:send(Sock, ServerIP, ServerPort, Pkt),
            bridge_loop(Bridge);
        {udp, Sock, _IP, _Port, Data} ->
            Bridge1 = Bridge#{answered := true},
            case maps:get(conn, Bridge) of
                undefined ->
                    Pending = maps:get(pending, Bridge),
                    bridge_loop(Bridge1#{pending := [Data | Pending]});
                Conn ->
                    deliver(Bridge, Conn, Data),
                    bridge_loop(Bridge1)
            end;
        stop ->
            gen_udp:close(Sock);
        _ ->
            bridge_loop(Bridge)
    end.

deliver(#{server := {ServerIP, ServerPort}, socket_ref := SocketRef}, Conn, Data) ->
    Conn ! {udp, SocketRef, ServerIP, ServerPort, Data}.

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
