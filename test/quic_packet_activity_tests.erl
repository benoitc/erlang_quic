%%% -*- erlang -*-
%%%
%%% QUIC Packet Activity Tests
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Tests for packet activity reporting (packets_sent, packets_received).
%%%
%%% These tests verify that the packet counters in quic_connection work
%%% correctly for liveness detection in distribution.
%%% @end

-module(quic_packet_activity_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Test Generators
%%====================================================================

%% Test that get_stats returns packet counts after handshake
get_stats_returns_counts_test_() ->
    {timeout, 30, fun test_get_stats_returns_counts/0}.

%% Test that packets_sent increments when sending data
packets_sent_increments_test_() ->
    {timeout, 30, fun test_packets_sent_increments/0}.

%% Test that counters are positive after handshake
counters_survive_handshake_test_() ->
    {timeout, 30, fun test_counters_survive_handshake/0}.

%%====================================================================
%% Setup Helpers
%%====================================================================

ensure_started() ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(quic).

generate_certs() ->
    TmpDir = filename:join([
        "/tmp", "quic_packet_test_" ++ integer_to_list(erlang:unique_integer([positive]))
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

cleanup(TmpDir, ServerName, ConnRef) ->
    catch quic:close(ConnRef, normal),
    timer:sleep(50),
    catch quic:stop_server(ServerName),
    catch os:cmd("rm -rf " ++ TmpDir),
    ok.

%%====================================================================
%% Tests
%%====================================================================

%% Test that get_stats returns a map with packet count keys
test_get_stats_returns_counts() ->
    ensure_started(),
    case generate_certs() of
        {ok, TmpDir, Cert, Key} ->
            ServerName = list_to_atom(
                "packet_test_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            try
                ServerOpts = #{
                    cert => Cert,
                    key => Key,
                    alpn => [<<"test">>]
                },
                {ok, _} = quic:start_server(ServerName, 0, ServerOpts),
                {ok, Port} = quic:get_server_port(ServerName),

                ClientOpts = #{
                    alpn => [<<"test">>],
                    verify => false
                },
                {ok, ConnRef} = quic:connect("127.0.0.1", Port, ClientOpts, self()),

                receive
                    {quic, ConnRef, {connected, _}} -> ok
                after 5000 ->
                    throw(connection_timeout)
                end,

                {ok, Stats} = quic:get_stats(ConnRef),

                ?assert(is_map(Stats)),
                ?assert(maps:is_key(packets_sent, Stats)),
                ?assert(maps:is_key(packets_received, Stats)),
                ?assert(maps:is_key(data_sent, Stats)),
                ?assert(maps:is_key(data_received, Stats)),

                ?assert(is_integer(maps:get(packets_sent, Stats))),
                ?assert(is_integer(maps:get(packets_received, Stats))),
                ?assert(maps:get(packets_sent, Stats) >= 0),
                ?assert(maps:get(packets_received, Stats) >= 0),

                cleanup(TmpDir, ServerName, ConnRef)
            catch
                Class:Reason ->
                    cleanup(TmpDir, ServerName, undefined),
                    erlang:raise(Class, Reason, [])
            end;
        {error, _Reason} ->
            %% Skip test if certs can't be generated
            ok
    end.

%% Test that packets_sent increments when sending data
test_packets_sent_increments() ->
    ensure_started(),
    case generate_certs() of
        {ok, TmpDir, Cert, Key} ->
            ServerName = list_to_atom(
                "packet_sent_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            try
                ServerOpts = #{
                    cert => Cert,
                    key => Key,
                    alpn => [<<"test">>]
                },
                {ok, _} = quic:start_server(ServerName, 0, ServerOpts),
                {ok, Port} = quic:get_server_port(ServerName),

                ClientOpts = #{
                    alpn => [<<"test">>],
                    verify => false
                },
                {ok, ConnRef} = quic:connect("127.0.0.1", Port, ClientOpts, self()),

                receive
                    {quic, ConnRef, {connected, _}} -> ok
                after 5000 ->
                    throw(connection_timeout)
                end,

                {ok, StatsBefore} = quic:get_stats(ConnRef),
                PacketsBefore = maps:get(packets_sent, StatsBefore),

                {ok, StreamId} = quic:open_stream(ConnRef),
                ok = quic:send_data(ConnRef, StreamId, <<"test data">>, true),

                timer:sleep(100),

                {ok, StatsAfter} = quic:get_stats(ConnRef),
                PacketsAfter = maps:get(packets_sent, StatsAfter),

                ?assert(PacketsAfter > PacketsBefore),

                cleanup(TmpDir, ServerName, ConnRef)
            catch
                Class:Reason ->
                    cleanup(TmpDir, ServerName, undefined),
                    erlang:raise(Class, Reason, [])
            end;
        {error, _Reason} ->
            ok
    end.

%% Test that counters work correctly during handshake
test_counters_survive_handshake() ->
    ensure_started(),
    case generate_certs() of
        {ok, TmpDir, Cert, Key} ->
            ServerName = list_to_atom(
                "handshake_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            try
                ServerOpts = #{
                    cert => Cert,
                    key => Key,
                    alpn => [<<"test">>]
                },
                {ok, _} = quic:start_server(ServerName, 0, ServerOpts),
                {ok, Port} = quic:get_server_port(ServerName),

                ClientOpts = #{
                    alpn => [<<"test">>],
                    verify => false
                },
                {ok, ConnRef} = quic:connect("127.0.0.1", Port, ClientOpts, self()),

                receive
                    {quic, ConnRef, {connected, _}} -> ok
                after 5000 ->
                    throw(connection_timeout)
                end,

                {ok, Stats} = quic:get_stats(ConnRef),

                %% Both counters should be positive after handshake completes
                ?assert(maps:get(packets_sent, Stats) > 0),
                ?assert(maps:get(packets_received, Stats) > 0),

                cleanup(TmpDir, ServerName, ConnRef)
            catch
                Class:Reason ->
                    cleanup(TmpDir, ServerName, undefined),
                    erlang:raise(Class, Reason, [])
            end;
        {error, _Reason} ->
            ok
    end.
