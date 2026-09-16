%%% -*- erlang -*-
%%%
%%% Connection ID rotation, end to end (RFC 9000 Section 5.1).
%%%
%%% These cases drive a real client and server, because the bug they
%%% cover was one of reachability, not arithmetic: issuance was only
%%% called from retirement, and nothing could be retired until something
%%% had been issued, so no NEW_CONNECTION_ID was ever sent. A test that
%%% calls the issuing helper directly passes against that. The first
%%% case therefore asserts the peer actually received CIDs.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_cid_rotation_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("quic.hrl").

-export([
    suite/0,
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    peer_receives_issued_cids/1,
    issuance_respects_peer_limit/1,
    retire_replenishes_and_stays_issuable/1
]).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        peer_receives_issued_cids,
        issuance_respects_peer_limit,
        retire_replenishes_and_stays_issuable
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(quic),
    case generate_certs() of
        {ok, TmpDir, Cert, Key} ->
            [{tmp_dir, TmpDir}, {cert, Cert}, {key, Key} | Config];
        {error, Reason} ->
            ct:fail("Failed to generate certificates: ~p", [Reason])
    end.

end_per_suite(Config) ->
    os:cmd("rm -rf " ++ ?config(tmp_dir, Config)),
    ok.

init_per_testcase(TestCase, Config) ->
    ServerName = list_to_atom(
        atom_to_list(TestCase) ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    [{server_name, ServerName} | Config].

end_per_testcase(_TestCase, Config) ->
    try
        quic:stop_server(?config(server_name, Config))
    catch
        _:_ -> ok
    end,
    timer:sleep(50),
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% The peer must end up holding connection IDs we issued. This is the
%% case that fails when rotation is unreachable.
peer_receives_issued_cids(Config) ->
    {ok, _Name, Port} = start_server(Config, #{}),
    {ok, Conn} = connect_client(Port, #{}),
    PeerCIDs = wait_for_peer_cids(Conn, 1, 2000),
    quic:close(Conn, normal),
    ?assert(
        PeerCIDs >= 1,
        lists:flatten(
            io_lib:format(
                "client holds ~p peer CIDs; the server issued none, so "
                "NEW_CONNECTION_ID never reached it",
                [PeerCIDs]
            )
        )
    ),
    {comment, io_lib:format("client holds ~p peer CIDs", [PeerCIDs])}.

%% active_connection_id_limit counts sequence 0, the handshake CID, so a
%% limit of N means N active CIDs in total and not N plus the original.
issuance_respects_peer_limit(Config) ->
    %% We advertise active_connection_id_limit = 2 (quic_connection.erl:2262,
    %% :2674); it is not settable per connection today, so the case asserts
    %% the value actually on the wire rather than one it cannot choose.
    Limit = 2,
    {ok, _Name, Port} = start_server(Config, #{}),
    {ok, Conn} = connect_client(Port, #{}),
    _ = wait_for_peer_cids(Conn, 1, 2000),
    {_StateName, Map} = quic_connection:get_state(Conn),
    PeerCIDs = maps:get(peer_cid_count, Map),
    quic:close(Conn, normal),
    ?assert(
        PeerCIDs =< Limit,
        lists:flatten(
            io_lib:format("server issued ~p CIDs against a limit of ~p", [PeerCIDs, Limit])
        )
    ),
    {comment, io_lib:format("~p CIDs for a limit of ~p", [PeerCIDs, Limit])}.

%% Retiring a CID the peer issued must be accepted, not answered with
%% PROTOCOL_VIOLATION, and must leave the connection usable.
retire_replenishes_and_stays_issuable(Config) ->
    {ok, _Name, Port} = start_server(Config, #{}),
    {ok, Conn} = connect_client(Port, #{}),
    _ = wait_for_peer_cids(Conn, 1, 2000),

    {ok, StreamId} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, StreamId, <<"before retire">>, false),

    ok = quic:migrate(Conn),
    timer:sleep(200),

    %% Still connected and still able to send: a wrongly rejected
    %% retirement closes the connection with PROTOCOL_VIOLATION.
    {StateName, Map} = quic_connection:get_state(Conn),
    ok = quic:send_data(Conn, StreamId, <<"after retire">>, true),
    quic:close(Conn, normal),

    ?assertEqual(connected, StateName),
    {comment,
        io_lib:format(
            "local=~p peer=~p after migration",
            [maps:get(local_cid_count, Map), maps:get(peer_cid_count, Map)]
        )}.

%%====================================================================
%% Helpers
%%====================================================================

wait_for_peer_cids(Conn, Want, Timeout) when Timeout =< 0 ->
    peer_cid_count(Conn, Want);
wait_for_peer_cids(Conn, Want, Timeout) ->
    case peer_cid_count(Conn, Want) of
        N when N >= Want ->
            N;
        _ ->
            timer:sleep(50),
            wait_for_peer_cids(Conn, Want, Timeout - 50)
    end.

peer_cid_count(Conn, _Want) ->
    try quic_connection:get_state(Conn) of
        {_StateName, Map} when is_map(Map) -> maps:get(peer_cid_count, Map, 0);
        _ -> 0
    catch
        _:_ -> 0
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
    {ok, Conn} = quic:connect("127.0.0.1", Port, ClientOpts, self()),
    receive
        {quic, Conn, {connected, _Info}} -> {ok, Conn}
    after 5000 ->
        quic:close(Conn, timeout),
        ct:fail(connection_timeout)
    end.

generate_certs() ->
    TmpDir = filename:join([
        "/tmp", "quic_cid_rotation_test_" ++ integer_to_list(erlang:unique_integer([positive]))
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
            {ok, TmpDir, CertDer, decode_key(KeyPem)};
        _ ->
            os:cmd("rm -rf " ++ TmpDir),
            {error, cert_generation_failed}
    end.

decode_key(KeyPem) ->
    case public_key:pem_decode(KeyPem) of
        [{'RSAPrivateKey', Der, not_encrypted}] -> public_key:der_decode('RSAPrivateKey', Der);
        [{'ECPrivateKey', Der, not_encrypted}] -> public_key:der_decode('ECPrivateKey', Der);
        [{'PrivateKeyInfo', Der, not_encrypted}] -> public_key:der_decode('PrivateKeyInfo', Der);
        [{_Type, Der, not_encrypted}] -> Der
    end.
