%%% -*- erlang -*-
%%%
%%% Regression test for issue #134: the server handshake flight must be
%%% segmented so no UDP datagram exceeds max_udp_payload_size. A strict
%%% client (Chromium) drops an oversized datagram and the handshake
%%% stalls.
%%%
%%% A gen_udp relay sits between the client and the echo server and
%%% records the byte size of every server-origin datagram. With a cert
%%% chain large enough to push the flight past 1200 bytes, the test
%%% asserts that no server datagram exceeds 1200 (the chunk budget).
%%% This fails on the pre-fix code (one ~4 KB handshake datagram).

-module(quic_handshake_mtu_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    server_flight_fits_max_udp_payload/1
]).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [server_flight_fits_max_udp_payload].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Test
%%====================================================================

server_flight_fits_max_udp_payload(_Config) ->
    %% Inflate the server's Certificate message well past 1200 bytes by
    %% padding the chain with extra cert DERs, forcing a multi-packet
    %% flight.
    CertDer = load_cert_der(),
    Chain = lists:duplicate(3, CertDer),
    {ok, Server} = quic_test_echo_server:start(#{cert_chain => Chain}),
    ServerPort = maps:get(port, Server),

    %% Relay between client and server; records server-origin datagram
    %% sizes.
    {Relay, RelayPort} = start_relay(ServerPort),
    try
        Opts = #{verify => false, alpn => [<<"echo">>]},
        {ok, ConnRef} = quic:connect(<<"127.0.0.1">>, RelayPort, Opts, self()),
        ok = wait_connected(ConnRef),
        ok = echo_roundtrip(ConnRef, <<"hello mtu">>),
        quic:close(ConnRef, normal),

        Tagged = relay_server_sizes(Relay),
        ct:pal("server datagrams {size, firstbyte}: ~p", [Tagged]),
        %% Issue #134 is about the handshake flight: the long-header
        %% Initial (0xC0-0xCF) and Handshake (0xE0-0xEF) packets, sent
        %% before PMTU is validated, must each fit the 1200 baseline.
        %% Post-handshake 1-RTT short-header packets (bit 7 = 0) are
        %% bounded by the peer's max_udp_payload_size, not 1200, so they
        %% are out of scope here.
        HandshakeSizes = [Sz || {Sz, FB} <- Tagged, FB >= 16#80],
        ?assert(HandshakeSizes =/= []),
        Max = lists:max(HandshakeSizes),
        ?assert(
            Max =< 1200,
            lists:flatten(
                io_lib:format(
                    "largest long-header (handshake) datagram ~p bytes exceeds 1200", [Max]
                )
            )
        )
    after
        stop_relay(Relay),
        quic_test_echo_server:stop(Server)
    end.

%%====================================================================
%% UDP relay
%%====================================================================

start_relay(ServerPort) ->
    Parent = self(),
    Pid = spawn_link(fun() ->
        {ok, Sock} = gen_udp:open(0, [binary, {active, true}, {reuseaddr, true}]),
        {ok, Port} = inet:port(Sock),
        Parent ! {relay_port, self(), Port},
        relay_loop(Sock, ServerPort, undefined, [])
    end),
    receive
        {relay_port, Pid, Port} -> {Pid, Port}
    after 5000 ->
        exit(relay_start_timeout)
    end.

relay_loop(Sock, ServerPort, ClientAddr, ServerSizes) ->
    receive
        {udp, Sock, {127, 0, 0, 1}, ServerPort, Data} ->
            %% From the server: record size (+ first byte = packet type),
            %% forward to the client.
            case ClientAddr of
                {CIP, CPort} -> gen_udp:send(Sock, CIP, CPort, Data);
                undefined -> ok
            end,
            <<FirstByte, _/binary>> = Data,
            relay_loop(Sock, ServerPort, ClientAddr, [{byte_size(Data), FirstByte} | ServerSizes]);
        {udp, Sock, FromIP, FromPort, Data} ->
            %% From the client: remember its address, forward to server.
            gen_udp:send(Sock, {127, 0, 0, 1}, ServerPort, Data),
            relay_loop(Sock, ServerPort, {FromIP, FromPort}, ServerSizes);
        {get_sizes, Caller} ->
            Caller ! {sizes, lists:reverse(ServerSizes)},
            relay_loop(Sock, ServerPort, ClientAddr, ServerSizes);
        stop ->
            gen_udp:close(Sock),
            ok
    end.

relay_server_sizes(Relay) ->
    Relay ! {get_sizes, self()},
    receive
        {sizes, Sizes} -> Sizes
    after 5000 ->
        []
    end.

stop_relay(Relay) ->
    Relay ! stop,
    ok.

%%====================================================================
%% Helpers
%%====================================================================

load_cert_der() ->
    CertFile = filename:join([code:lib_dir(quic), "..", "..", "certs", "cert.pem"]),
    {ok, Pem} =
        case filelib:is_file(CertFile) of
            true -> file:read_file(CertFile);
            false -> generate_cert_pem()
        end,
    [{'Certificate', Der, _} | _] = public_key:pem_decode(Pem),
    Der.

generate_cert_pem() ->
    Dir = "/tmp/quic_mtu_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Cert = filename:join(Dir, "cert.pem"),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -keyout ~s/key.pem -out ~s "
            "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
            [Dir, Cert]
        )
    ),
    os:cmd(Cmd),
    file:read_file(Cert).

wait_connected(ConnRef) ->
    receive
        {quic, ConnRef, {connected, _Info}} -> ok
    after 10000 ->
        catch quic:close(ConnRef, timeout),
        ct:fail("connection timeout")
    end.

echo_roundtrip(ConnRef, Payload) ->
    {ok, StreamId} = quic:open_stream(ConnRef),
    ok = quic:send_data(ConnRef, StreamId, Payload, true),
    receive
        {quic, ConnRef, {stream_data, StreamId, Got, true}} ->
            ?assertEqual(Payload, Got),
            ok
    after 10000 ->
        ct:fail("echo timeout")
    end.
