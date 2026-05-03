%%% -*- erlang -*-
%%%
%%% Tests for quic:get_path_stats/1.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_path_stats_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Test Generators
%%====================================================================

post_handshake_test_() ->
    {timeout, 30, fun test_post_handshake/0}.

not_connected_test_() ->
    {timeout, 15, fun test_not_connected/0}.

concurrent_calls_test_() ->
    {timeout, 30, fun test_concurrent_calls/0}.

%%====================================================================
%% Tests
%%====================================================================

%% After handshake + a round-trip of data, the snapshot has positive
%% srtt + min_rtt and a positive cwnd, plus all the documented keys.
test_post_handshake() ->
    ensure_started(),
    case generate_certs() of
        {error, _} ->
            ok;
        {ok, TmpDir, Cert, Key} ->
            ServerName = unique_name("path_stats"),
            try
                {ok, _} = quic:start_server(ServerName, 0, #{
                    cert => Cert, key => Key, alpn => [<<"test">>]
                }),
                {ok, Port} = quic:get_server_port(ServerName),
                {ok, Conn} = quic:connect(
                    "127.0.0.1",
                    Port,
                    #{
                        alpn => [<<"test">>], verify => false
                    },
                    self()
                ),
                ok = wait_connected(Conn, 5000),

                %% Drive at least one round-trip so RTT samples land.
                {ok, StreamId} = quic:open_stream(Conn),
                ok = quic:send_data(Conn, StreamId, <<"hello path">>, true),
                timer:sleep(150),

                {ok, Stats} = quic:get_path_stats(Conn),
                ?assert(is_map(Stats)),
                lists:foreach(
                    fun(K) -> ?assert(maps:is_key(K, Stats)) end,
                    [
                        srtt,
                        latest_rtt,
                        min_rtt,
                        rtt_var,
                        cwnd,
                        bytes_in_flight,
                        in_recovery,
                        congested
                    ]
                ),
                ?assert(is_integer(maps:get(srtt, Stats))),
                ?assert(is_integer(maps:get(min_rtt, Stats))),
                ?assert(is_integer(maps:get(cwnd, Stats))),
                ?assert(is_boolean(maps:get(in_recovery, Stats))),
                ?assert(is_boolean(maps:get(congested, Stats))),
                %% RTT samples are non-negative; loopback round-trips
                %% can round to 0 ms, so don't require strictly > 0.
                ?assert(maps:get(srtt, Stats) >= 0),
                ?assert(maps:get(min_rtt, Stats) >= 0),
                ?assert(maps:get(cwnd, Stats) > 0),

                cleanup(TmpDir, ServerName, Conn)
            catch
                Class:Reason:Stack ->
                    cleanup(TmpDir, ServerName, undefined),
                    erlang:raise(Class, Reason, Stack)
            end
    end.

%% A connection that has not finished the handshake must return
%% {error, not_connected} cleanly without crashing the connection
%% process or the caller.
test_not_connected() ->
    ensure_started(),
    %% Connect to a port nothing is listening on; the connection
    %% process exists in handshaking state until it times out.
    DeadPort = pick_dead_port(),
    case
        quic:connect(
            "127.0.0.1",
            DeadPort,
            #{
                alpn => [<<"test">>], verify => false
            },
            self()
        )
    of
        {ok, Conn} ->
            try
                ?assertEqual({error, not_connected}, quic:get_path_stats(Conn)),
                %% Process must still be alive (no crash).
                ?assert(is_process_alive(Conn))
            after
                catch quic:close(Conn, normal)
            end;
        {error, _} ->
            %% Connect failed synchronously; the {error, _} guarantee
            %% in get_path_stats is moot. Treat as skipped.
            ok
    end.

%% Many concurrent callers must all complete within a reasonable
%% deadline. gen_statem:call serialises against the connection's own
%% mailbox, but the call is O(1) so 64 in-flight calls finish quickly.
test_concurrent_calls() ->
    ensure_started(),
    case generate_certs() of
        {error, _} ->
            ok;
        {ok, TmpDir, Cert, Key} ->
            ServerName = unique_name("path_stats_conc"),
            try
                {ok, _} = quic:start_server(ServerName, 0, #{
                    cert => Cert, key => Key, alpn => [<<"test">>]
                }),
                {ok, Port} = quic:get_server_port(ServerName),
                {ok, Conn} = quic:connect(
                    "127.0.0.1",
                    Port,
                    #{
                        alpn => [<<"test">>], verify => false
                    },
                    self()
                ),
                ok = wait_connected(Conn, 5000),

                Parent = self(),
                Refs = [
                    begin
                        Ref = make_ref(),
                        spawn_link(fun() ->
                            Result = quic:get_path_stats(Conn),
                            Parent ! {Ref, Result}
                        end),
                        Ref
                    end
                 || _ <- lists:seq(1, 64)
                ],
                ok = collect(Refs, 5000),

                cleanup(TmpDir, ServerName, Conn)
            catch
                Class:Reason:Stack ->
                    cleanup(TmpDir, ServerName, undefined),
                    erlang:raise(Class, Reason, Stack)
            end
    end.

%%====================================================================
%% Helpers
%%====================================================================

ensure_started() ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(quic).

unique_name(Prefix) ->
    list_to_atom(Prefix ++ "_" ++ integer_to_list(erlang:unique_integer([positive]))).

generate_certs() ->
    TmpDir = filename:join([
        "/tmp", "quic_path_stats_" ++ integer_to_list(erlang:unique_integer([positive]))
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

wait_connected(Conn, Timeout) ->
    receive
        {quic, Conn, {connected, _}} -> ok
    after Timeout ->
        throw(connection_timeout)
    end.

pick_dead_port() ->
    {ok, S} = gen_udp:open(0, [binary]),
    {ok, P} = inet:port(S),
    gen_udp:close(S),
    P.

collect([], _Timeout) ->
    ok;
collect([Ref | Rest], Timeout) ->
    receive
        {Ref, {ok, Stats}} when is_map(Stats) ->
            collect(Rest, Timeout);
        {Ref, Other} ->
            erlang:error({unexpected_path_stats_result, Other})
    after Timeout ->
        erlang:error({path_stats_timeout, length(Rest) + 1})
    end.

cleanup(TmpDir, ServerName, ConnRef) ->
    case ConnRef of
        undefined -> ok;
        _ -> catch quic:close(ConnRef, normal)
    end,
    timer:sleep(50),
    catch quic:stop_server(ServerName),
    catch os:cmd("rm -rf " ++ TmpDir),
    ok.
