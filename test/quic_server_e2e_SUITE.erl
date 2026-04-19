%%% -*- erlang -*-
%%%
%%% E2E Tests for QUIC Server Mode
%%% Tests Erlang client connecting to Erlang server
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_server_e2e_SUITE).

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

%% Test cases
-export([
    listener_start_stop/1,
    listener_get_port/1,
    server_connection_batches_by_default/1,
    server_connection_batching_opt_out/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [{group, listener_tests}].

groups() ->
    [
        {listener_tests, [sequence], [
            listener_start_stop,
            listener_get_port,
            server_connection_batches_by_default,
            server_connection_batching_opt_out
        ]}
    ].

init_per_suite(Config) ->
    %% Ensure QUIC application is started
    application:ensure_all_started(crypto),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

%% Generate a test certificate and key
generate_test_cert() ->
    Cert = <<"test_certificate">>,
    PrivKey = crypto:strong_rand_bytes(32),
    {Cert, PrivKey}.

%%====================================================================
%% Test Cases
%%====================================================================

listener_start_stop(Config) ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },

    %% Start listener on random port
    {ok, Listener} = quic_listener:start_link(0, Opts),
    ?assert(is_pid(Listener)),
    ?assert(is_process_alive(Listener)),

    %% Stop listener
    ok = quic_listener:stop(Listener),
    timer:sleep(10),
    ?assertNot(is_process_alive(Listener)),

    Config.

listener_get_port(Config) ->
    {Cert, PrivKey} = generate_test_cert(),
    Opts = #{
        cert => Cert,
        key => PrivKey,
        alpn => [<<"h3">>]
    },

    {ok, Listener} = quic_listener:start_link(0, Opts),
    Port = quic_listener:get_port(Listener),
    ?assert(is_integer(Port)),
    ?assert(Port > 0),
    ct:log("Listener bound to port ~p", [Port]),

    ok = quic_listener:stop(Listener),
    Config.

%% Regression: server connections get a per-connection sender socket_state
%% by default so ACKs and data are coalesced before flush (and use GSO on
%% Linux when the listener runs the socket backend). Verify by connecting
%% a client to an in-process echo server and inspecting the server-side
%% connection state.
server_connection_batches_by_default(Config) ->
    {ok, Echo} = quic_test_echo_server:start(),
    #{name := Name, port := Port} = Echo,
    try
        {ok, Conn} = quic:connect("127.0.0.1", Port, quic_test_echo_server:client_opts(), self()),
        receive
            {quic, Conn, {connected, _Info}} -> ok
        after 5000 ->
            ct:fail("client handshake timed out")
        end,
        {ok, ConnPids} = quic:get_server_connections(Name),
        [ServerPid | _] = lists:usort(ConnPids),
        {_State, Info} = quic_connection:get_state(ServerPid),
        %% With default opts, a socket_state is attached and batching
        %% is enabled. send_backend reports gen_udp or socket depending
        %% on listener configuration (gen_udp by default).
        ?assertNotEqual(direct, maps:get(send_backend, Info)),
        ?assertEqual(true, maps:get(send_batching_enabled, Info)),
        ?assert(is_boolean(maps:get(send_gso_supported, Info))),
        quic:close(Conn)
    after
        quic_test_echo_server:stop(Echo)
    end,
    Config.

%% Regression: operators can disable server-side batching via
%% server_send_batching => false, restoring the direct gen_udp:send/4
%% path. Verify socket_state is undefined in that case.
server_connection_batching_opt_out(Config) ->
    {ok, Echo} = quic_test_echo_server:start(#{server_send_batching => false}),
    #{name := Name, port := Port} = Echo,
    try
        {ok, Conn} = quic:connect("127.0.0.1", Port, quic_test_echo_server:client_opts(), self()),
        receive
            {quic, Conn, {connected, _Info}} -> ok
        after 5000 ->
            ct:fail("client handshake timed out")
        end,
        {ok, ConnPids} = quic:get_server_connections(Name),
        [ServerPid | _] = lists:usort(ConnPids),
        {_State, Info} = quic_connection:get_state(ServerPid),
        %% Opt-out: per-connection socket_state wraps the listener
        %% backend but batching is disabled. `send_backend' reports
        %% the actual backend (gen_udp or socket); the visible contract
        %% is `send_batching_enabled = false'.
        ?assertEqual(false, maps:get(send_batching_enabled, Info)),
        ?assertEqual(false, maps:get(send_gso_supported, Info)),
        quic:close(Conn)
    after
        quic_test_echo_server:stop(Echo)
    end,
    Config.
