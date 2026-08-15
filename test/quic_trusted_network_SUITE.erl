%%% -*- erlang -*-
%%%
%%% Trusted-network configurations still encrypt the wire.
%%%
%%% QUIC has no unauthenticated or cleartext mode (RFC 9001 §3), so
%%% the two ways to drop PKI ceremony on an internal subnet -- skipping
%%% certificate validation, or replacing certificates with a TLS 1.3
%%% external PSK -- leave packet protection intact. Each case drives a
%%% real handshake through a recording UDP relay and asserts the
%%% application payload never appears in any datagram.
%%%
%%% See docs/INTERNAL_NETWORKS.md.
%%%

-module(quic_trusted_network_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    relay_captures_cleartext/1,
    verify_none_encrypts_wire/1,
    psk_only_encrypts_wire/1,
    no_auth_method_rejected/1,
    verify_defaults_to_validating/1,
    verify_none_spellings_equivalent/1
]).

-define(IDENTITY, <<"alice">>).
-define(SECRET, <<"this-is-a-32-byte-test-secret!!!">>).
-define(LOOPBACK, {127, 0, 0, 1}).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        relay_captures_cleartext,
        verify_none_encrypts_wire,
        psk_only_encrypts_wire,
        no_auth_method_rejected,
        verify_defaults_to_validating,
        verify_none_spellings_equivalent
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Test cases
%%====================================================================

%% Control case: the relay does capture what crosses it. Without
%% this, the two encryption tests below could pass on a broken
%% capture that records nothing.
relay_captures_cleartext(_Config) ->
    Marker = marker(),
    {ok, Sink} = gen_udp:open(0, [binary, {active, false}, {ip, ?LOOPBACK}]),
    {ok, SinkPort} = inet:port(Sink),
    {ok, Relay, RelayPort} = start_relay(SinkPort),
    try
        {ok, Sender} = gen_udp:open(0, [binary, {active, false}, {ip, ?LOOPBACK}]),
        ok = gen_udp:send(Sender, ?LOOPBACK, RelayPort, Marker),
        {ok, {_, _, Marker}} = gen_udp:recv(Sink, 0, 5000),
        ok = gen_udp:close(Sender),
        ?assert(contains(captured(Relay), Marker))
    after
        stop_relay(Relay),
        gen_udp:close(Sink)
    end.

%% Certificate auth with `verify => verify_none' on the client: no CA
%% to maintain, but the handshake and the echoed payload are still
%% AEAD-protected.
verify_none_encrypts_wire(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{}),
    run_encrypted_echo(Server, #{verify => verify_none}).

%% PSK-only server: no certificate anywhere, mutual authentication
%% from the shared secret. Packet protection is unchanged.
psk_only_encrypts_wire(_Config) ->
    {ok, Server} = start_psk_only_server(),
    run_encrypted_echo(Server, #{
        verify => verify_none,
        external_psk => {?IDENTITY, ?SECRET}
    }).

%% There is no way to ask for a listener with neither certificates
%% nor a PSK -- the unauthenticated configuration is refused.
no_auth_method_rejected(_Config) ->
    Name = list_to_atom("quic_trusted_noauth_" ++ unique()),
    ?assertEqual(
        {error, no_auth_method},
        quic:start_server(Name, 0, #{alpn => [<<"echo">>]})
    ).

%% Skipping validation is opt-in: with no `verify' option the client
%% validates and rejects the server's self-signed certificate.
verify_defaults_to_validating(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{}),
    try
        ?assertMatch({error, _}, try_connect(Server, #{}))
    after
        stop_server(Server)
    end.

%% `verify_none', `none' and `false' are the same option value.
verify_none_spellings_equivalent(_Config) ->
    {ok, Server} = quic_test_echo_server:start(#{}),
    try
        [
            ?assertEqual(ok, try_connect(Server, #{verify => V}))
         || V <- [verify_none, none, false]
        ]
    after
        stop_server(Server)
    end.

%%====================================================================
%% Encrypted-echo driver
%%====================================================================

%% Echo a distinctive marker through a relay sitting between client
%% and server, then assert the marker appears in no captured datagram
%% in either direction.
run_encrypted_echo(Server, ClientOpts) ->
    Marker = marker(),
    #{port := ServerPort} = Server,
    {ok, Relay, RelayPort} = start_relay(ServerPort),
    try
        Opts = maps:merge(#{alpn => [<<"echo">>]}, ClientOpts),
        {ok, ConnRef} = quic:connect(<<"127.0.0.1">>, RelayPort, Opts, self()),
        wait_connected(ConnRef),
        ok = echo_roundtrip(ConnRef, Marker),
        quic:close(ConnRef, normal),
        Datagrams = captured(Relay),
        %% Handshake plus data in both directions: a handful of
        %% datagrams at minimum. Guards against asserting over an
        %% empty capture.
        ?assert(length(Datagrams) >= 4),
        ?assertNot(contains(Datagrams, Marker))
    after
        stop_relay(Relay),
        stop_server(Server)
    end.

%% 64 bytes of random data, hex-encoded so a cleartext copy would be
%% unmistakable in a capture and can't collide with protocol bytes.
marker() ->
    binary:encode_hex(crypto:strong_rand_bytes(32)).

contains(Datagrams, Marker) ->
    lists:any(
        fun(D) -> binary:match(D, Marker) =/= nomatch end,
        Datagrams
    ).

%%====================================================================
%% Recording UDP relay
%%====================================================================

%% Forwards datagrams between one client and the server, keeping a
%% copy of everything that crosses it.
start_relay(ServerPort) ->
    Parent = self(),
    Pid = spawn_link(fun() -> relay_init(Parent, ServerPort) end),
    receive
        {relay_ready, Pid, Port} -> {ok, Pid, Port}
    after 5000 ->
        ct:fail("relay did not start")
    end.

stop_relay(Relay) ->
    unlink(Relay),
    Relay ! stop,
    ok.

captured(Relay) ->
    Relay ! {captured, self()},
    receive
        {captured, Relay, Datagrams} -> Datagrams
    after 5000 ->
        ct:fail("relay did not report captures")
    end.

relay_init(Parent, ServerPort) ->
    {ok, Sock} = gen_udp:open(0, [binary, {active, true}, {ip, ?LOOPBACK}]),
    {ok, Port} = inet:port(Sock),
    Parent ! {relay_ready, self(), Port},
    relay_loop(Sock, ServerPort, undefined, []).

relay_loop(Sock, ServerPort, Client, Acc) ->
    receive
        {udp, Sock, ?LOOPBACK, ServerPort, Data} when Client =/= undefined ->
            {ClientIP, ClientPort} = Client,
            ok = gen_udp:send(Sock, ClientIP, ClientPort, Data),
            relay_loop(Sock, ServerPort, Client, [Data | Acc]);
        {udp, Sock, IP, Port, Data} ->
            ok = gen_udp:send(Sock, ?LOOPBACK, ServerPort, Data),
            relay_loop(Sock, ServerPort, {IP, Port}, [Data | Acc]);
        {captured, From} ->
            From ! {captured, self(), lists:reverse(Acc)},
            relay_loop(Sock, ServerPort, Client, Acc);
        stop ->
            gen_udp:close(Sock)
    end.

%%====================================================================
%% Servers
%%====================================================================

%% Listener authenticated by PSK alone -- no cert, no key.
start_psk_only_server() ->
    Name = list_to_atom("quic_trusted_psk_" ++ unique()),
    Opts = #{
        alpn => [<<"echo">>],
        psks => #{?IDENTITY => ?SECRET},
        connection_handler => fun(ConnPid, _ConnRef) ->
            Echo = spawn_link(fun() -> echo_loop(ConnPid) end),
            ok = quic:set_owner_sync(ConnPid, Echo),
            {ok, Echo}
        end
    },
    {ok, _Pid} = quic:start_server(Name, 0, Opts),
    {ok, Port} = quic:get_server_port(Name),
    {ok, #{name => Name, port => Port}}.

stop_server(#{name := Name}) ->
    try
        quic:stop_server(Name)
    catch
        _:_ -> ok
    end,
    ok.

echo_loop(Conn) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            _ = quic:send_data_async(Conn, StreamId, Data, Fin),
            echo_loop(Conn);
        {quic, Conn, {closed, _Reason}} ->
            ok;
        {'DOWN', _, process, Conn, _} ->
            ok;
        _Other ->
            echo_loop(Conn)
    end.

%%====================================================================
%% Client helpers
%%====================================================================

%% Drive a connect that may legitimately fail. `ok' on a completed
%% handshake, `{error, Reason}' otherwise.
try_connect(#{port := Port}, ExtraOpts) ->
    Opts = maps:merge(#{alpn => [<<"echo">>]}, ExtraOpts),
    case quic:connect(<<"127.0.0.1">>, Port, Opts, self()) of
        {error, _} = Error ->
            Error;
        {ok, ConnRef} ->
            receive
                {quic, ConnRef, {connected, _Info}} ->
                    quic:close(ConnRef, normal),
                    ok;
                {quic, ConnRef, {error, Reason}} ->
                    {error, Reason};
                {quic, ConnRef, {closed, Reason}} ->
                    {error, Reason}
            after 10000 ->
                quic:safe_close(ConnRef, timeout),
                {error, timeout}
            end
    end.

wait_connected(ConnRef) ->
    receive
        {quic, ConnRef, {connected, _Info}} -> ok
    after 10000 ->
        quic:safe_close(ConnRef, timeout),
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

unique() ->
    integer_to_list(erlang:unique_integer([positive, monotonic])).
