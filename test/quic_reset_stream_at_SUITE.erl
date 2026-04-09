%%% -*- erlang -*-
%%%
%%% RESET_STREAM_AT End-to-End Test Suite
%%% draft-ietf-quic-reliable-stream-reset-07
%%%
%%% Tests the RESET_STREAM_AT extension between erlang_quic client and server.

-module(quic_reset_stream_at_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("quic.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases - Transport Parameter
-export([
    transport_param_negotiation/1,
    transport_param_not_advertised/1
]).

%% Test cases - Basic Functionality
-export([
    reset_stream_at_basic/1,
    reset_stream_at_zero_reliable_size/1,
    reset_stream_at_full_reliable_size/1,
    reset_stream_at_partial_data/1
]).

%% Test cases - Error Handling
-export([
    reset_stream_at_invalid_reliable_size/1,
    reset_stream_at_not_supported/1
]).

%% Test cases - Multiple Frames
-export([
    reset_stream_at_reduce_reliable_size/1,
    reset_stream_at_ignore_increased_reliable_size/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [
        {group, transport_param},
        {group, basic},
        {group, error_handling},
        {group, multiple_frames}
    ].

groups() ->
    [
        {transport_param, [sequence], [
            transport_param_negotiation,
            transport_param_not_advertised
        ]},
        {basic, [sequence], [
            reset_stream_at_basic,
            reset_stream_at_zero_reliable_size,
            reset_stream_at_full_reliable_size,
            reset_stream_at_partial_data
        ]},
        {error_handling, [sequence], [
            reset_stream_at_invalid_reliable_size,
            reset_stream_at_not_supported
        ]},
        {multiple_frames, [sequence], [
            reset_stream_at_reduce_reliable_size,
            reset_stream_at_ignore_increased_reliable_size
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),
    application:ensure_all_started(quic),

    %% Generate test certificates using openssl
    case generate_certs() of
        {ok, TmpDir, CertDer, KeyDer} ->
            [
                {tmp_dir, TmpDir},
                {server_cert, CertDer},
                {server_key, KeyDer}
                | Config
            ];
        {error, Reason} ->
            ct:fail("Failed to generate certificates: ~p", [Reason])
    end.

end_per_suite(Config) ->
    TmpDir = proplists:get_value(tmp_dir, Config, undefined),
    case TmpDir of
        undefined -> ok;
        _ -> os:cmd("rm -rf " ++ TmpDir)
    end,
    application:stop(quic),
    ok.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting test: ~p", [TestCase]),
    %% Generate unique server name
    ServerName = list_to_atom(
        atom_to_list(TestCase) ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    [{server_name, ServerName} | Config].

end_per_testcase(TestCase, Config) ->
    ct:pal("Finished test: ~p", [TestCase]),
    ServerName = ?config(server_name, Config),
    catch quic:stop_server(ServerName),
    timer:sleep(50),
    ok.

%%====================================================================
%% Transport Parameter Tests
%%====================================================================

%% Test that transport parameter is properly negotiated
transport_param_negotiation(Config) ->
    ServerCert = ?config(server_cert, Config),
    ServerKey = ?config(server_key, Config),
    ServerName = ?config(server_name, Config),

    %% Start server with RESET_STREAM_AT support
    ServerOpts = #{
        cert => ServerCert,
        key => ServerKey,
        alpn => [<<"test">>],
        reset_stream_at => true
    },
    {ok, _} = quic:start_server(ServerName, 0, ServerOpts),
    {ok, Port} = quic:get_server_port(ServerName),

    %% Connect client with RESET_STREAM_AT support
    ClientOpts = #{
        verify => false,
        alpn => [<<"test">>],
        reset_stream_at => true
    },
    {ok, ClientRef} = quic:connect("127.0.0.1", Port, ClientOpts, self()),

    %% Wait for client connection
    receive
        {quic, ClientRef, {connected, ClientInfo}} ->
            ct:pal("Client connected: ~p", [ClientInfo]),
            %% Verify transport param was negotiated
            TP = maps:get(transport_params, ClientInfo, #{}),
            ?assertEqual(true, maps:get(reset_stream_at, TP, false))
    after 5000 ->
        ct:fail("Client connection timeout")
    end,

    quic:close(ClientRef),
    ok.

%% Test behavior when transport parameter is not advertised
transport_param_not_advertised(Config) ->
    ServerCert = ?config(server_cert, Config),
    ServerKey = ?config(server_key, Config),
    ServerName = ?config(server_name, Config),

    %% Start server WITHOUT RESET_STREAM_AT support
    ServerOpts = #{
        cert => ServerCert,
        key => ServerKey,
        alpn => [<<"test">>]
    },
    {ok, _} = quic:start_server(ServerName, 0, ServerOpts),
    {ok, Port} = quic:get_server_port(ServerName),

    %% Connect client with RESET_STREAM_AT support
    ClientOpts = #{
        verify => false,
        alpn => [<<"test">>],
        reset_stream_at => true
    },
    {ok, ClientRef} = quic:connect("127.0.0.1", Port, ClientOpts, self()),

    receive
        {quic, ClientRef, {connected, ClientInfo}} ->
            ct:pal("Client connected: ~p", [ClientInfo]),
            TP = maps:get(transport_params, ClientInfo, #{}),
            %% Server didn't advertise support
            ?assertEqual(false, maps:get(reset_stream_at, TP, false))
    after 5000 ->
        ct:fail("Client connection timeout")
    end,

    quic:close(ClientRef),
    ok.

%%====================================================================
%% Basic Functionality Tests
%%====================================================================

%% Test basic RESET_STREAM_AT functionality
reset_stream_at_basic(Config) ->
    {ClientRef, _ServerConn, _ServerName} = setup_connection(Config),

    %% Open a stream and send some data
    {ok, StreamId} = quic:open_stream(ClientRef),
    ok = quic:send_data(ClientRef, StreamId, <<"hello world">>, false),
    ok = quic:send_data(ClientRef, StreamId, <<"more data here">>, false),

    timer:sleep(50),

    %% Reset with reliable delivery of first 11 bytes ("hello world")
    ok = quic:reset_stream_at(ClientRef, StreamId, 16#100, 11),

    %% Give time for processing
    timer:sleep(100),

    quic:close(ClientRef),
    ok.

%% Test RESET_STREAM_AT with ReliableSize=0 (equivalent to RESET_STREAM)
reset_stream_at_zero_reliable_size(Config) ->
    {ClientRef, _ServerConn, _ServerName} = setup_connection(Config),

    {ok, StreamId} = quic:open_stream(ClientRef),
    ok = quic:send_data(ClientRef, StreamId, <<"data that won't be delivered">>, false),

    timer:sleep(50),

    %% Reset with ReliableSize=0 - no data needs to be delivered
    ok = quic:reset_stream_at(ClientRef, StreamId, 16#200, 0),

    timer:sleep(100),

    quic:close(ClientRef),
    ok.

%% Test RESET_STREAM_AT with ReliableSize=FinalSize (all data delivered)
reset_stream_at_full_reliable_size(Config) ->
    {ClientRef, _ServerConn, _ServerName} = setup_connection(Config),

    {ok, StreamId} = quic:open_stream(ClientRef),
    Data = <<"all this data must be delivered">>,
    DataLen = byte_size(Data),
    ok = quic:send_data(ClientRef, StreamId, Data, false),

    timer:sleep(50),

    %% Reset with ReliableSize = all data sent
    ok = quic:reset_stream_at(ClientRef, StreamId, 16#300, DataLen),

    timer:sleep(100),

    quic:close(ClientRef),
    ok.

%% Test partial data delivery
reset_stream_at_partial_data(Config) ->
    {ClientRef, _ServerConn, _ServerName} = setup_connection(Config),

    {ok, StreamId} = quic:open_stream(ClientRef),

    %% Send data in chunks
    ok = quic:send_data(ClientRef, StreamId, <<"chunk1:">>, false),
    ok = quic:send_data(ClientRef, StreamId, <<"chunk2:">>, false),
    ok = quic:send_data(ClientRef, StreamId, <<"chunk3:">>, false),

    timer:sleep(50),

    %% Reset after first two chunks (14 bytes: "chunk1:chunk2:")
    ok = quic:reset_stream_at(ClientRef, StreamId, 16#400, 14),

    %% The reliable data should be delivered, chunk3 may or may not be
    %% This is a behavioral test - we just verify no crash occurs

    quic:close(ClientRef),
    ok.

%%====================================================================
%% Error Handling Tests
%%====================================================================

%% Test that invalid ReliableSize (> send_offset) returns error
reset_stream_at_invalid_reliable_size(Config) ->
    {ClientRef, _ServerConn, _ServerName} = setup_connection(Config),

    {ok, StreamId} = quic:open_stream(ClientRef),
    %% Send only 5 bytes
    ok = quic:send_data(ClientRef, StreamId, <<"hello">>, false),

    timer:sleep(50),

    %% Try to reset with ReliableSize > data sent
    Result = quic:reset_stream_at(ClientRef, StreamId, 16#500, 100),
    ?assertMatch({error, {invalid_reliable_size, 100, _}}, Result),

    quic:close(ClientRef),
    ok.

%% Test that calling reset_stream_at when peer doesn't support it fails
reset_stream_at_not_supported(Config) ->
    ServerCert = ?config(server_cert, Config),
    ServerKey = ?config(server_key, Config),
    ServerName = ?config(server_name, Config),

    %% Start server WITHOUT RESET_STREAM_AT support
    ServerOpts = #{
        cert => ServerCert,
        key => ServerKey,
        alpn => [<<"test">>]
    },
    {ok, _} = quic:start_server(ServerName, 0, ServerOpts),
    {ok, Port} = quic:get_server_port(ServerName),

    ClientOpts = #{
        verify => false,
        alpn => [<<"test">>],
        reset_stream_at => true
    },
    {ok, ClientRef} = quic:connect("127.0.0.1", Port, ClientOpts, self()),

    receive
        {quic, ClientRef, {connected, _}} -> ok
    after 5000 ->
        ct:fail("Connection timeout")
    end,

    {ok, StreamId} = quic:open_stream(ClientRef),
    ok = quic:send_data(ClientRef, StreamId, <<"data">>, false),

    timer:sleep(50),

    %% Should fail because server doesn't support RESET_STREAM_AT
    Result = quic:reset_stream_at(ClientRef, StreamId, 16#600, 2),
    ?assertEqual({error, not_supported}, Result),

    quic:close(ClientRef),
    ok.

%%====================================================================
%% Multiple Frames Tests
%%====================================================================

%% Test reducing ReliableSize via subsequent frames
reset_stream_at_reduce_reliable_size(Config) ->
    {ClientRef, _ServerConn, _ServerName} = setup_connection(Config),

    {ok, StreamId} = quic:open_stream(ClientRef),
    ok = quic:send_data(ClientRef, StreamId, <<"0123456789">>, false),

    timer:sleep(50),

    %% First reset with ReliableSize=10
    ok = quic:reset_stream_at(ClientRef, StreamId, 16#700, 10),

    %% Reduce ReliableSize to 5 (allowed per spec)
    ok = quic:reset_stream_at(ClientRef, StreamId, 16#700, 5),

    quic:close(ClientRef),
    ok.

%% Test that increasing ReliableSize fails
reset_stream_at_ignore_increased_reliable_size(Config) ->
    {ClientRef, _ServerConn, _ServerName} = setup_connection(Config),

    {ok, StreamId} = quic:open_stream(ClientRef),
    ok = quic:send_data(ClientRef, StreamId, <<"0123456789">>, false),

    timer:sleep(50),

    %% First reset with ReliableSize=5
    ok = quic:reset_stream_at(ClientRef, StreamId, 16#800, 5),

    %% Try to increase ReliableSize to 10 - should fail
    Result = quic:reset_stream_at(ClientRef, StreamId, 16#800, 10),
    ?assertEqual({error, cannot_increase_reliable_size}, Result),

    quic:close(ClientRef),
    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

setup_connection(Config) ->
    ServerCert = ?config(server_cert, Config),
    ServerKey = ?config(server_key, Config),
    ServerName = ?config(server_name, Config),

    ServerOpts = #{
        cert => ServerCert,
        key => ServerKey,
        alpn => [<<"test">>],
        reset_stream_at => true
    },
    {ok, _} = quic:start_server(ServerName, 0, ServerOpts),
    {ok, Port} = quic:get_server_port(ServerName),

    ClientOpts = #{
        verify => false,
        alpn => [<<"test">>],
        reset_stream_at => true
    },
    {ok, ClientRef} = quic:connect("127.0.0.1", Port, ClientOpts, self()),

    %% Wait for client connection
    receive
        {quic, ClientRef, {connected, _}} -> ok
    after 5000 ->
        ct:fail("Client connection timeout")
    end,

    %% Get server connection
    ServerConn =
        receive
            {quic, Conn, {connected, _}} when Conn =/= ClientRef -> Conn
        after 1000 ->
            undefined
        end,

    {ClientRef, ServerConn, ServerName}.

%%====================================================================
%% Certificate Generation
%%====================================================================

generate_certs() ->
    TmpDir = filename:join([
        "/tmp",
        "quic_reset_stream_at_test_" ++
            integer_to_list(erlang:unique_integer([positive]))
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
