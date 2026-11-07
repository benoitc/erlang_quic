%%% -*- erlang -*-
%%%
%%% RFC 9000 §14: UDP datagrams must not be fragmented at the IP layer
%%% and DF must be set where possible. On Linux every QUIC socket uses
%%% IP_PMTUDISC_PROBE (and IPV6_PMTUDISC_PROBE on IPv6 sockets, which
%%% also carry IPv4-mapped traffic), so a datagram larger than the
%%% interface MTU fails with EMSGSIZE instead of leaving in fragments.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_socket_dont_fragment_tests).

-include_lib("eunit/include/eunit.hrl").

-define(IP_MTU_DISCOVER, 10).
-define(IPV6_MTU_DISCOVER, 23).
-define(PMTUDISC_PROBE, 3).

dont_fragment_test_() ->
    case os:type() of
        {unix, linux} ->
            [
                {"listener socket backend", fun listener_socket_backend/0},
                {"listener socket backend, IPv6", fun listener_socket_backend_inet6/0},
                {"listener gen_udp backend", fun listener_genudp_backend/0},
                {"listener gen_udp backend, dual stack", fun listener_genudp_backend_dual_stack/0},
                {"client socket backend", fun client_socket_backend/0},
                {"client socket backend, IPv6", fun client_socket_backend_inet6/0},
                {"client gen_udp backend", fun client_genudp_backend/0},
                {"client gen_udp backend, IPv6", fun client_genudp_backend_inet6/0},
                {"connection gen_udp client socket", fun connection_client_socket/0},
                {"connection gen_udp client socket, IPv6", fun connection_client_socket_inet6/0},
                {"connection rebind", fun connection_rebind/0},
                {"listener preferred-address sockets", fun preferred_address_sockets/0},
                {"oversized datagram is not fragmented", fun oversized_datagram_not_fragmented/0}
            ];
        _ ->
            []
    end.

listener_socket_backend() ->
    with_state(quic_socket:open_socket_backend(0, inet, #{}, batch_config()), fun(S) ->
        ?assertEqual([?PMTUDISC_PROBE], mtu_discover(quic_socket:get_socket(S), [ip]))
    end).

listener_socket_backend_inet6() ->
    with_state(quic_socket:open_socket_backend(0, inet6, #{}, batch_config()), fun(S) ->
        ?assertEqual(
            [?PMTUDISC_PROBE, ?PMTUDISC_PROBE], mtu_discover(quic_socket:get_socket(S), [ip, ipv6])
        )
    end).

listener_genudp_backend() ->
    with_state(quic_socket:open_genudp_backend(0, #{}, batch_config()), fun(S) ->
        ?assertEqual([?PMTUDISC_PROBE], mtu_discover(quic_socket:get_socket(S), [ip]))
    end).

listener_genudp_backend_dual_stack() ->
    Opts = #{extra_socket_opts => [inet6, {ipv6_v6only, false}]},
    with_state(quic_socket:open_genudp_backend(0, Opts, batch_config()), fun(S) ->
        ?assertEqual(
            [?PMTUDISC_PROBE, ?PMTUDISC_PROBE], mtu_discover(quic_socket:get_socket(S), [ip, ipv6])
        )
    end).

client_socket_backend() ->
    with_state(open_for_send({127, 0, 0, 1}, socket), fun(S) ->
        ?assertEqual([?PMTUDISC_PROBE], mtu_discover(quic_socket:get_socket(S), [ip]))
    end).

client_socket_backend_inet6() ->
    with_state(open_for_send({0, 0, 0, 0, 0, 0, 0, 1}, socket), fun(S) ->
        ?assertEqual(
            [?PMTUDISC_PROBE, ?PMTUDISC_PROBE], mtu_discover(quic_socket:get_socket(S), [ip, ipv6])
        )
    end).

client_genudp_backend() ->
    with_state(open_for_send({127, 0, 0, 1}, gen_udp), fun(S) ->
        ?assertEqual([?PMTUDISC_PROBE], mtu_discover(quic_socket:get_socket(S), [ip]))
    end).

client_genudp_backend_inet6() ->
    with_state(open_for_send({0, 0, 0, 0, 0, 0, 0, 1}, gen_udp), fun(S) ->
        ?assertEqual(
            [?PMTUDISC_PROBE, ?PMTUDISC_PROBE], mtu_discover(quic_socket:get_socket(S), [ip, ipv6])
        )
    end).

connection_client_socket() ->
    {ok, Socket, _, true} = quic_connection:open_client_socket_genudp({127, 0, 0, 1}, #{}, []),
    try
        ?assertEqual([?PMTUDISC_PROBE], mtu_discover(Socket, [ip]))
    after
        gen_udp:close(Socket)
    end.

connection_client_socket_inet6() ->
    {ok, Socket, _, true} =
        quic_connection:open_client_socket_genudp({0, 0, 0, 0, 0, 0, 0, 1}, #{}, []),
    try
        ?assertEqual([?PMTUDISC_PROBE, ?PMTUDISC_PROBE], mtu_discover(Socket, [ip, ipv6]))
    after
        gen_udp:close(Socket)
    end.

connection_rebind() ->
    {ok, Old} = gen_udp:open(0, [binary, inet, {active, false}]),
    {ok, New} = quic_connection:rebind_socket(Old, inet),
    try
        ?assertEqual([?PMTUDISC_PROBE], mtu_discover(New, [ip]))
    after
        gen_udp:close(New)
    end.

preferred_address_sockets() ->
    {ok, Main} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    Opts = #{
        preferred_ipv4 => {{127, 0, 0, 1}, 0}, preferred_ipv6 => {{0, 0, 0, 0, 0, 0, 0, 1}, 0}
    },
    {ok, [V4, V6] = Preferred} = quic_listener:open_preferred_sockets(Main, Opts),
    try
        ?assertEqual([?PMTUDISC_PROBE], mtu_discover(V4, [ip])),
        ?assertEqual([?PMTUDISC_PROBE, ?PMTUDISC_PROBE], mtu_discover(V6, [ip, ipv6]))
    after
        lists:foreach(fun gen_udp:close/1, [Main | Preferred])
    end.

%% A datagram above the route MTU to a TEST-NET-1 address (RFC 5737):
%% fragmented and sent without DF, it is accepted by the kernel.
oversized_datagram_not_fragmented() ->
    case route_mtu({192, 0, 2, 1}) of
        undefined ->
            ok;
        MTU ->
            with_state(open_for_send({192, 0, 2, 1}, gen_udp), fun(S) ->
                ?assertEqual(
                    {error, emsgsize},
                    quic_socket:send_immediate(S, {192, 0, 2, 1}, 9, binary:copy(<<0>>, MTU))
                )
            end)
    end.

batch_config() ->
    #{batching_enabled => false, max_batch => 1}.

open_for_send(IP, Backend) ->
    quic_socket:open_for_send(IP, #{backend => Backend, batching => #{enabled => false}}).

with_state({ok, State}, F) ->
    try
        F(State)
    after
        quic_socket:close(State)
    end.

mtu_discover(Socket, Levels) ->
    [getopt(Socket, Level) || Level <- Levels].

getopt({'$socket', _} = Socket, ip) ->
    {ok, V} = socket:getopt_native(Socket, {ip, ?IP_MTU_DISCOVER}, integer),
    V;
getopt({'$socket', _} = Socket, ipv6) ->
    {ok, V} = socket:getopt_native(Socket, {ipv6, ?IPV6_MTU_DISCOVER}, integer),
    V;
getopt(Socket, ip) ->
    {ok, [{raw, _, _, <<V:32/native>>}]} = inet:getopts(Socket, [{raw, 0, ?IP_MTU_DISCOVER, 4}]),
    V;
getopt(Socket, ipv6) ->
    {ok, [{raw, _, _, <<V:32/native>>}]} = inet:getopts(Socket, [{raw, 41, ?IPV6_MTU_DISCOVER, 4}]),
    V.

route_mtu(IP) ->
    {ok, S} = socket:open(inet, dgram, udp),
    try socket:connect(S, #{family => inet, addr => IP, port => 9}) of
        ok ->
            case socket:getopt(S, {ip, mtu}) of
                {ok, MTU} when MTU < 65000 -> MTU;
                _ -> undefined
            end;
        {error, _} ->
            undefined
    after
        socket:close(S)
    end.
