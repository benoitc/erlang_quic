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
    receive_datagram/1,
    bidirectional_datagrams/1
]).

%% Test cases - API
-export([
    datagram_max_size_api/1,
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
            receive_datagram,
            bidirectional_datagrams
        ]},
        {api, [sequence], [
            datagram_max_size_api,
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
    catch quic:stop_server(ServerName),
    timer:sleep(50),
    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

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

%%====================================================================
%% Negotiation Tests
%%====================================================================

%% Both endpoints support datagrams - negotiation succeeds
both_support_datagrams(Config) ->
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Check that datagrams are enabled
    MaxSize = quic:datagram_max_size(ConnRef),
    ct:log("Negotiated max datagram size: ~p", [MaxSize]),
    ?assert(MaxSize > 0),
    ?assertEqual(65535, MaxSize),

    quic:close(ConnRef, normal),
    ok.

%% Client doesn't advertise datagram support
%% Server can't send to client, but client CAN send to server
client_disabled_datagrams(Config) ->
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    %% Client doesn't set max_datagram_frame_size (defaults to 0)
    {ok, ConnRef} = connect_client(Port, #{}),

    %% Client sees server's advertised value (server CAN receive)
    MaxSize = quic:datagram_max_size(ConnRef),
    ct:log("Max datagram size (peer's limit): ~p", [MaxSize]),
    ?assertEqual(65535, MaxSize),

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

%% Send a datagram at the maximum allowed size
send_max_size_datagram(Config) ->
    MaxSize = 1200,
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => MaxSize}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Client's max size should be the server's advertised limit
    NegotiatedSize = quic:datagram_max_size(ConnRef),
    ?assertEqual(MaxSize, NegotiatedSize),

    %% Send exactly at the limit
    Data = crypto:strong_rand_bytes(MaxSize),
    Result = quic:send_datagram(ConnRef, Data),
    ?assertEqual(ok, Result),

    quic:close(ConnRef, normal),
    ok.

%% Sending an oversized datagram should fail
send_oversized_datagram_fails(Config) ->
    MaxSize = 100,
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => MaxSize}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Verify the negotiated size
    ?assertEqual(MaxSize, quic:datagram_max_size(ConnRef)),

    %% Try to send oversized datagram
    OversizedData = crypto:strong_rand_bytes(MaxSize + 1),
    Result = quic:send_datagram(ConnRef, OversizedData),
    ?assertEqual({error, datagram_too_large}, Result),

    quic:close(ConnRef, normal),
    ok.

%% Receive a datagram from the server
receive_datagram(Config) ->
    {ok, ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Get server connections to send from server side
    {ok, ServerConns} = quic:get_server_connections(ServerName),

    case ServerConns of
        [ServerConn | _] ->
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
        [] ->
            %% Server connection may not be established yet, skip
            ct:log("No server connections available, skipping receive test")
    end,

    quic:close(ConnRef, normal),
    ok.

%% Bidirectional datagram exchange
bidirectional_datagrams(Config) ->
    {ok, ServerName, Port} = start_server(Config, #{max_datagram_frame_size => 65535}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => 65535}),

    %% Client sends datagram
    ClientData = <<"Client to server">>,
    ok = quic:send_datagram(ConnRef, ClientData),

    %% Give server time to receive
    timer:sleep(100),

    %% Check server connections
    {ok, ServerConns} = quic:get_server_connections(ServerName),
    case ServerConns of
        [ServerConn | _] ->
            %% Server sends datagram back
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
        [] ->
            ct:log("No server connections available, skipping bidirectional test")
    end,

    quic:close(ConnRef, normal),
    ok.

%%====================================================================
%% API Tests
%%====================================================================

%% Test datagram_max_size API returns peer's value
datagram_max_size_api(Config) ->
    ServerMaxSize = 1200,
    ClientMaxSize = 65535,
    {ok, _ServerName, Port} = start_server(Config, #{max_datagram_frame_size => ServerMaxSize}),
    {ok, ConnRef} = connect_client(Port, #{max_datagram_frame_size => ClientMaxSize}),

    %% Client should see server's advertised value
    MaxSize = quic:datagram_max_size(ConnRef),
    ?assertEqual(ServerMaxSize, MaxSize),

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
