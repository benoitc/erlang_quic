%%% -*- erlang -*-
%%%
%%% A large server flight has to reach the wire intact.
%%%
%%% The server's Certificate message carries the whole chain, so a real
%%% deployment with intermediates runs to tens of kilobytes: far more
%%% than the initial congestion window, and more still once a Retry adds
%%% a round trip before it. Every packet the window holds back is queued
%%% and sent later, and CRYPTO is a reliable ordered stream, so losing
%%% one queued fragment leaves the client a gap it can never fill and
%%% the handshake never completes.
%%%
%%% This reproduces that on a live connection rather than on the queue
%%% alone. `address_validation => always' puts a Retry in front of the
%%% flight, which also settles the address, so the congestion window is
%%% the only thing holding packets back and the queue is what has to
%%% carry them.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_large_handshake_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([large_chain_handshake_after_retry/1]).

%% Filler certificates in the chain. Each is about 1.2 KB of DER, so
%% this puts the Certificate message well past 30 KB: more than twenty
%% Handshake packets.
-define(CHAIN_LEN, 28).

%% Two datagrams, the RFC 9002 floor. The default window passes a chain
%% this size in one go on loopback, so nothing would be queued and the
%% suite would prove nothing.
-define(INITIAL_WINDOW, 2400).

-define(ECHO, <<"the whole chain arrived">>).
-define(CONNECT_MS, 30000).
-define(ECHO_MS, 30000).

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [large_chain_handshake_after_retry].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    Dir = filename:join(?config(priv_dir, Config), "chain"),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Chain = generate_chain(Dir, ?CHAIN_LEN),
    Bytes = lists:sum([byte_size(C) || C <- Chain]),
    ct:pal("chain: ~p certificates, ~p bytes", [length(Chain), Bytes]),
    %% The point of the suite is a flight the window cannot pass in one
    %% go; assert the fixture actually is one.
    ?assert(Bytes > 16 * 1200),
    [{chain, Chain} | Config].

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% The shape this was first reported in: a certificate flight past the
%% window, behind a Retry.
large_chain_handshake_after_retry(Config) ->
    ?assertEqual(?ECHO, run(?config(chain, Config), always)).

%%====================================================================
%% Harness
%%====================================================================

run(Chain, Validation) ->
    {ok, Server} = quic_test_echo_server:start(#{
        cert_chain => Chain,
        address_validation => Validation,
        initial_window => ?INITIAL_WINDOW
    }),
    try
        Port = maps:get(port, Server),
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{alpn => [<<"echo">>]}),
        {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?CONNECT_MS ->
            ct:fail("connect timeout with ~p-certificate chain", [length(Chain)])
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, ?ECHO, true),
        Got = await_echo(Conn, StreamId),
        _ = quic:safe_close(Conn, normal),
        Got
    after
        quic_test_echo_server:stop(Server)
    end.

await_echo(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} -> Data;
        {quic, Conn, _Other} -> await_echo(Conn, StreamId)
    after ?ECHO_MS -> timeout
    end.

%%====================================================================
%% Fixture
%%====================================================================

%% Distinct self-signed certificates standing in for a chain of
%% intermediates. The client runs with verify => false, so what matters
%% is the size and ordering of the Certificate message, not a path that
%% builds.
generate_chain(Dir, Count) ->
    Key = filename:join(Dir, "filler.key"),
    "" = os:cmd("openssl genrsa -out " ++ Key ++ " 2048 2>/dev/null"),
    [filler_cert(Dir, Key, N) || N <- lists:seq(1, Count)].

filler_cert(Dir, Key, N) ->
    Out = filename:join(Dir, "filler-" ++ integer_to_list(N) ++ ".pem"),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -new -key ~s -out ~s -days 1 "
            "-subj '/CN=intermediate-~p.quic.test' 2>/dev/null",
            [Key, Out, N]
        )
    ),
    _ = os:cmd(Cmd),
    {ok, Pem} = file:read_file(Out),
    [{'Certificate', Der, _}] = public_key:pem_decode(Pem),
    Der.
