%%% -*- erlang -*-
%%%
%%% E2E Tests for QUIC Datagram Extension (RFC 9221)
%%%
%%% Tests max_datagram_frame_size transport parameter negotiation
%%% between Erlang client and server.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_datagram_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("quic.hrl").

%% Payload of a DATAGRAM in a 1200-byte packet: flags, the server's
%% 8-byte connection ID, a 4-byte packet number, the AEAD tag, the frame
%% type and a 2-byte length.
-define(PATH_BUDGET_1200, (1200 - (1 + 8 + 4 + 16) - (1 + 2))).

%% CT callbacks
-export([
    suite/0,
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases - Negotiation
-export([
    both_support_datagrams/1,
    client_disabled_datagrams/1,
    server_disabled_datagrams/1,
    neither_supports_datagrams/1
]).

%% Test cases - Data Transfer
-export([
    send_small_datagram/1,
    send_max_size_datagram/1,
    send_oversized_datagram_fails/1,
    send_oversized_for_path_fails/1,
    receive_datagram/1,
    bidirectional_datagrams/1
]).

%% Test cases - API
-export([
    datagram_max_size_api/1,
    datagram_max_size_fits_the_path/1,
    datagram_max_size_when_disabled/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        {group, negotiation},
        {group, data_transfer},
        {group, api}
    ].

groups() ->
    [
        {negotiation, [sequence], [
            both_support_datagrams,
            client_disabled_datagrams,
            server_disabled_datagrams,
            neither_supports_datagrams
        ]},
        {data_transfer, [sequence], [
            send_small_datagram,
            send_max_size_datagram,
            send_oversized_datagram_fails,
            send_oversized_for_path_fails,
            receive_datagram,
            bidirectional_datagrams
        ]},
        {api, [sequence], [
            datagram_max_size_api,
            datagram_max_size_fits_the_path,
            datagram_max_size_when_disabled
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(quic),

    %% Generate test certificates
    case generate_certs() of
        {ok, TmpDir, Cert, Key} ->
            [{tmp_dir, TmpDir}, {cert, Cert}, {key, Key} | Config];
        {error, Reason} ->
            ct:fail("Failed to generate certificates: ~p", [Reason])
    end.

end_per_suite(Config) ->
    TmpDir = ?config(tmp_dir, Config),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:log("Starting test: ~p", [TestCase]),
    %% Generate unique server name
    ServerName = list_to_atom(
        atom_to_list(TestCase) ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    [{server_name, ServerName} | Config].

end_per_testcase(_TestCase, Config) ->
    ServerName = ?config(server_name, Config),
    try
        quic:stop_server(ServerName)
    catch
        _:_ -> ok
    end,
    timer:sleep(50),
    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

peer_max_datagram_frame_size(ConnRef) ->
    {ok, Params} = quic:get_peer_transport_params(ConnRef),
    maps:get(max_datagram_frame_size, Params, 0).

generate_certs() ->
    TmpDir = filename:join([
        "/tmp", "quic_datagram_test_" ++ integer_to_list(erlang:unique_integer([positive]))
    ]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    CertFile = filename:join(TmpDir, "cert.pem"),
    KeyFile = filename:join(TmpDir, "key.pem"),
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile]
    ),
    os:cmd(lists:flatten(Cmd)),

    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            {ok, CertPem} = file:read_file(CertFile),
            {ok, KeyPem} = file:read_file(KeyFile),
            [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
            KeyDer = decode_key(KeyPem),
            {ok, TmpDir, CertDer, KeyDer};
        _ ->
            os:cmd("rm -rf " ++ TmpDir),
            {error, cert_generation_failed}
    end.

decode_key(KeyPem) ->
    case public_key:pem_decode(KeyPem) of
        [{'RSAPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('RSAPrivateKey', Der);
        [{'ECPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('ECPrivateKey', Der);
        [{'PrivateKeyInfo', Der, not_encrypted}] ->
            public_key:der_decode('PrivateKeyInfo', Der);
        [{_Type, Der, not_encrypted}] ->
            Der
    end.

start_server(Config, ExtraOpts) ->
    Cert = ?config(cert, Config),
    Key = ?config(key, Config),
    ServerName = ?config(server_name, Config),

    ServerOpts = maps:merge(
        #{cert => Cert, key => Key, alpn => [<<"test">>]},
        ExtraOpts
    ),
    {ok, _} = quic:start_server(ServerName, 0, ServerOpts),
    {ok, Port} = quic:get_server_port(ServerName),
    {ok, ServerName, Port}.

connect_client(Port, ExtraOpts) ->
    ClientOpts = maps:merge(
        #{alpn => [<<"test">>], verify => false},
        ExtraOpts
    ),
    {ok, ConnRef} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
    receive
        {quic, ConnRef, {connected, _Info}} ->
            {ok, ConnRef}
    after 5000 ->
        quic:close(ConnRef, timeout),
        {error, connection_timeout}
    end.

%% @doc Wait for a server connection to be in connected state
wait_for_server_connection(ServerName, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_for_server_connection_loop(ServerName, Deadline).

wait_for_server_connection_loop(ServerName, Deadline) ->
    Now = erlang:monotonic_time(millisecond),
    case Now > Deadline of
        true ->
            {error, timeout};
        false ->
            case quic:get_server_connections(ServerName) of
                {ok, []} ->
                    timer:sleep(10),
                    wait_for_server_connection_loop(ServerName, Deadline);
                {ok, Conns} ->
                    case find_connected(Conns) of
                        {ok, ConnPid} ->
                            {ok, ConnPid};
                        not_found ->
                            timer:sleep(10),
                            wait_for_server_connection_loop(ServerName, Deadline)
                    end;
                {error, _} = Error ->
                    Error
            end
    end.

find_connected([]) ->
    not_found;
find_connected([Conn | Rest]) ->
    try
        case quic_connection:get_state(Conn) of
            {connected, _} -> {ok, Conn};
            _ -> find_connected(Rest)
        end
    catch
        _:_ -> find_connected(Rest)
    end.

%%====================================================================
%% Negotiation Tests
%%====================================================================

%% Both endpoints support datagrams - negotiation succeeds
both_support_datagrams(Config) ->
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% The peer's limit is negotiated; the path bounds what fits.
    ?assertEqual(65535, peer_max_datagram_frame_size(ConnRef)),
    MaxSize = quic:datagram_max_size(ConnRef),
    ct:log("Largest datagram payload: ~p", [MaxSize]),
    ?assert(MaxSize > 0),
    ?assert(MaxSize < 1500),

    quic:close(ConnRef, normal),
    ok.

%% Client doesn't advertise datagram support
%% Server can't send to client, but client CAN send to server
client_disabled_datagrams(Config) ->
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    %% Client doesn't set max_datagram_frame_size (defaults to 0)
    {ok, ConnRef} = connect_client(Port, #{}),

    %% Client sees server's advertised value (server CAN receive)
    ?assertEqual(65535, peer_max_datagram_frame_size(ConnRef)),
    ?assert(quic:datagram_max_size(ConnRef) > 0),

    %% Client CAN send to server (server advertised support)
    Result = quic:send_datagram(ConnRef, <<"test">>),
    ?assertEqual(ok, Result),

    quic:close(ConnRef, normal),
    ok.

%% Server doesn't advertise datagram support
server_disabled_datagrams(Config) ->
    %% Server doesn't set max_datagram_frame_size (defaults to 0)
    {ok, _ServerName, Port} = start_server(Config, #{}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Datagrams should be disabled (server didn't advertise)
    MaxSize = quic:datagram_max_size(ConnRef),
    ct:log("Max datagram size with server disabled: ~p", [MaxSize]),
    ?assertEqual(0, MaxSize),

    %% Sending should fail
    Result = quic:send_datagram(ConnRef, <<"test">>),
    ?assertEqual({error, datagrams_not_supported}, Result),

    quic:close(ConnRef, normal),
    ok.

%% Neither endpoint supports datagrams
neither_supports_datagrams(Config) ->
    {ok, _ServerName, Port} = start_server(Config, #{}),
    {ok, ConnRef} = connect_client(Port, #{}),

    MaxSize = quic:datagram_max_size(ConnRef),
    ?assertEqual(0, MaxSize),

    Result = quic:send_datagram(ConnRef, <<"test">>),
    ?assertEqual({error, datagrams_not_supported}, Result),

    quic:close(ConnRef, normal),
    ok.

%%====================================================================
%% Data Transfer Tests
%%====================================================================

%% Send a small datagram
send_small_datagram(Config) ->
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    Data = <<"Hello, datagram!">>,
    Result = quic:send_datagram(ConnRef, Data),
    ?assertEqual(ok, Result),

    quic:close(ConnRef, normal),
    ok.

%% Send a datagram at a size the PMTU budget can actually fit. The peer
%% may advertise 65535, but on a 1200-byte PMTU we must leave headroom
%% for the QUIC short-header and frame framing.
send_max_size_datagram(Config) ->
    MaxSize = 65535,
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => MaxSize}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Client sees the server's advertised limit
    ?assertEqual(MaxSize, peer_max_datagram_frame_size(ConnRef)),

    %% Send a payload that fits under both the peer's advertised cap and
    %% the current PMTU budget.
    Data = crypto:strong_rand_bytes(1100),
    Result = quic:send_datagram(ConnRef, Data),
    ?assertEqual(ok, Result),

    quic:close(ConnRef, normal),
    ok.

%% A datagram that fits the peer's advertised max but exceeds the
%% local PMTU budget must be rejected with a distinguishable error so
%% callers can retry after PMTU grows.
send_oversized_for_path_fails(Config) ->
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Peer accepts up to 65535 but the path MTU is ~1200 on loopback.
    Data = crypto:strong_rand_bytes(4096),
    ?assertEqual(
        {error, datagram_too_large_for_path},
        quic:send_datagram(ConnRef, Data)
    ),

    quic:close(ConnRef, normal),
    ok.

%% The peer's limit covers the whole frame, so a 100-byte limit leaves
%% 97 bytes after the frame type and a 2-byte length (RFC 9221 Section 3).
send_oversized_datagram_fails(Config) ->
    MaxSize = 100,
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => MaxSize}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    ?assertEqual(MaxSize, peer_max_datagram_frame_size(ConnRef)),
    ?assertEqual(97, quic:datagram_max_size(ConnRef)),
    ?assertEqual(ok, quic:send_datagram(ConnRef, crypto:strong_rand_bytes(97))),
    ?assertEqual(
        {error, datagram_too_large}, quic:send_datagram(ConnRef, crypto:strong_rand_bytes(98))
    ),

    quic:close(ConnRef, normal),
    ok.

%% Receive a datagram from the server
receive_datagram(Config) ->
    {ok, ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Wait for server connection to be established
    case wait_for_server_connection(ServerName, 5000) of
        {ok, ServerConn} ->
            %% Server sends datagram to client
            TestData = <<"Hello from server!">>,
            ok = quic:send_datagram(ServerConn, TestData),

            %% Client should receive the datagram
            receive
                {quic, ConnRef, {datagram, ReceivedData}} ->
                    ct:log("Received datagram: ~p", [ReceivedData]),
                    ?assertEqual(TestData, ReceivedData)
            after 5000 ->
                ct:fail("Timeout waiting for datagram")
            end;
        {error, timeout} ->
            ct:fail("Server connection not established within timeout")
    end,

    quic:close(ConnRef, normal),
    ok.

%% Bidirectional datagram exchange
bidirectional_datagrams(Config) ->
    {ok, ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Wait for server connection to be established
    case wait_for_server_connection(ServerName, 5000) of
        {ok, ServerConn} ->
            %% Client sends datagram
            ClientData = <<"Client to server">>,
            ok = quic:send_datagram(ConnRef, ClientData),

            %% Server sends datagram back (no artificial delay needed)
            ServerData = <<"Server to client">>,
            ok = quic:send_datagram(ServerConn, ServerData),

            %% Client receives server's datagram
            receive
                {quic, ConnRef, {datagram, ReceivedData}} ->
                    ct:log("Client received: ~p", [ReceivedData]),
                    ?assertEqual(ServerData, ReceivedData)
            after 5000 ->
                ct:fail("Timeout waiting for server datagram")
            end;
        {error, timeout} ->
            ct:fail("Server connection not established within timeout")
    end,

    quic:close(ConnRef, normal),
    ok.

%%====================================================================
%% API Tests
%%====================================================================

%% A peer limit of 1200 leaves 1197 bytes of frame payload, but a packet
%% at the 1200-byte path MTU carries less: the path decides.
datagram_max_size_api(Config) ->
    ServerMaxSize = 1200,
    ClientMaxSize = 65535,
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => ServerMaxSize}),
    {ok, ConnRef} = connect_client(Port, #{
        max_datagram_frame_size => ClientMaxSize, pmtu_enabled => false
    }),

    ?assertEqual(ServerMaxSize, peer_max_datagram_frame_size(ConnRef)),
    ?assertEqual(?PATH_BUDGET_1200, quic:datagram_max_size(ConnRef)),

    quic:close(ConnRef, normal),
    ok.

%% Right after connecting, the size reported is what send_datagram
%% accepts at the confirmed MTU: exactly that size goes through, one
%% byte more is refused for the path (RFC 8899 Section 3).
datagram_max_size_fits_the_path(Config) ->
    {ok, ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{
        max_datagram_frame_size => 65535, pmtu_enabled => false
    }),
    {ok, ServerConn} = wait_for_server_connection(ServerName, 5000),
    ok = quic:set_owner_sync(ServerConn, self()),

    ?assertEqual({ok, 1200}, quic:get_mtu(ConnRef)),
    MaxSize = quic:datagram_max_size(ConnRef),
    ?assertEqual(?PATH_BUDGET_1200, MaxSize),
    Data = crypto:strong_rand_bytes(MaxSize),
    ?assertEqual(ok, quic:send_datagram(ConnRef, Data)),
    ?assertEqual(
        {error, datagram_too_large_for_path},
        quic:send_datagram(ConnRef, crypto:strong_rand_bytes(MaxSize + 1))
    ),
    receive
        {quic, ServerConn, {datagram, Data}} -> ok
    after 5000 ->
        ct:fail("Timeout waiting for the full-size datagram")
    end,

    quic:close(ConnRef, normal),
    ok.

%% Test datagram_max_size returns 0 when disabled
datagram_max_size_when_disabled(Config) ->
    {ok, _ServerName, Port} = start_server(Config, #{}),
    {ok, ConnRef} = connect_client(Port, #{}),

    MaxSize = quic:datagram_max_size(ConnRef),
    ?assertEqual(0, MaxSize),

    quic:close(ConnRef, normal),
    ok.
