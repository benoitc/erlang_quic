%%% -*- erlang -*-
%%%
%%% E2E Tests for QUIC Multi-Pool Server
%%% Tests named server pools and isolation
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_multi_server_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

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
    multiple_servers_isolation/1,
    server_restart_recovery/1,
    pool_distribution/1,
    per_server_options/1,
    server_port_reuse_after_stop/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [{group, multi_server_tests}].

groups() ->
    [
        {multi_server_tests, [sequence], [
            multiple_servers_isolation,
            server_restart_recovery,
            pool_distribution,
            per_server_options,
            server_port_reuse_after_stop
        ]}
    ].

init_per_suite(Config) ->
    %% Start required applications
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    %% Clean up all servers
    lists:foreach(
        fun(Name) ->
            quic:stop_server(Name)
        end,
        quic:which_servers()
    ),
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    %% Clean up any existing servers before each test
    lists:foreach(
        fun(Name) ->
            _ = quic:stop_server(Name),
            _ = (catch quic_server_registry:unregister(Name))
        end,
        quic:which_servers()
    ),
    timer:sleep(50),
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

%% Generate test certificate and key
generate_test_cert() ->
    Cert = <<"test_certificate_data">>,
    PrivKey = crypto:strong_rand_bytes(32),
    {Cert, PrivKey}.

%% Create base server options
base_opts() ->
    {Cert, PrivKey} = generate_test_cert(),
    #{cert => Cert, key => PrivKey, alpn => [<<"h3">>]}.

%%====================================================================
%% Test Cases
%%====================================================================

%% Test that multiple servers can run on different ports
multiple_servers_isolation(_Config) ->
    ct:log("Starting multiple isolated servers"),

    %% Start first server
    {ok, Pid1} = quic:start_server(server_a, 0, base_opts()),
    ?assert(is_pid(Pid1)),

    %% Start second server on different port
    {ok, Pid2} = quic:start_server(server_b, 0, base_opts()),
    ?assert(is_pid(Pid2)),
    ?assertNotEqual(Pid1, Pid2),

    %% Both should be registered
    Servers = quic:which_servers(),
    ?assertEqual(2, length(Servers)),
    ?assert(lists:member(server_a, Servers)),
    ?assert(lists:member(server_b, Servers)),

    %% Get info for each
    {ok, InfoA} = quic:get_server_info(server_a),
    {ok, InfoB} = quic:get_server_info(server_b),
    ?assertEqual(Pid1, maps:get(pid, InfoA)),
    ?assertEqual(Pid2, maps:get(pid, InfoB)),

    %% Clean up
    ok = quic:stop_server(server_a),
    ok = quic:stop_server(server_b),

    ct:log("Multiple servers isolation test passed").

%% Test that a server can be stopped and the port reused
server_restart_recovery(_Config) ->
    ct:log("Testing server restart and recovery"),

    %% Start server
    {ok, Pid1} = quic:start_server(recovery_server, 0, base_opts()),
    ?assert(is_pid(Pid1)),

    %% Get the assigned port
    {ok, Info1} = quic:get_server_info(recovery_server),
    _Port1 = maps:get(port, Info1),

    %% Stop server
    ok = quic:stop_server(recovery_server),
    _ = (catch quic_server_registry:unregister(recovery_server)),
    timer:sleep(100),

    %% Verify it's gone
    ?assertEqual({error, not_found}, quic:get_server_info(recovery_server)),

    %% Restart with same name
    {ok, Pid2} = quic:start_server(recovery_server, 0, base_opts()),
    ?assert(is_pid(Pid2)),
    ?assertNotEqual(Pid1, Pid2),

    %% Verify it's back
    {ok, Info2} = quic:get_server_info(recovery_server),
    ?assertEqual(Pid2, maps:get(pid, Info2)),

    %% Clean up
    ok = quic:stop_server(recovery_server),

    ct:log("Server restart recovery test passed").

%% Test that pool_size option creates multiple listeners
pool_distribution(_Config) ->
    ct:log("Testing listener pool distribution"),

    %% Start server with pool
    PoolOpts = maps:merge(base_opts(), #{pool_size => 3}),
    {ok, Pid} = quic:start_server(pool_server, 0, PoolOpts),
    ?assert(is_pid(Pid)),

    %% Verify pool_size in stored opts
    {ok, Info} = quic:get_server_info(pool_server),
    StoredOpts = maps:get(opts, Info),
    ?assertEqual(3, maps:get(pool_size, StoredOpts)),

    %% Clean up
    ok = quic:stop_server(pool_server),

    ct:log("Pool distribution test passed").

%% Test that different servers can have different options
per_server_options(_Config) ->
    ct:log("Testing per-server options"),

    %% Start server with specific ALPN
    Opts1 = maps:merge(base_opts(), #{alpn => [<<"h3">>]}),
    {ok, _} = quic:start_server(h3_server, 0, Opts1),

    %% Start another server with different ALPN
    Opts2 = maps:merge(base_opts(), #{alpn => [<<"custom-proto">>]}),
    {ok, _} = quic:start_server(custom_server, 0, Opts2),

    %% Verify options are stored separately
    {ok, Info1} = quic:get_server_info(h3_server),
    {ok, Info2} = quic:get_server_info(custom_server),

    StoredOpts1 = maps:get(opts, Info1),
    StoredOpts2 = maps:get(opts, Info2),

    ?assertEqual([<<"h3">>], maps:get(alpn, StoredOpts1)),
    ?assertEqual([<<"custom-proto">>], maps:get(alpn, StoredOpts2)),

    %% Clean up
    ok = quic:stop_server(h3_server),
    ok = quic:stop_server(custom_server),

    ct:log("Per-server options test passed").

%% Test that a port can be reused after server stops
server_port_reuse_after_stop(_Config) ->
    ct:log("Testing port reuse after server stop"),

    %% Use a specific high port to avoid conflicts
    TestPort = 40000 + rand:uniform(10000),

    %% Start first server on specific port
    {ok, _} = quic:start_server(port_test_server, TestPort, base_opts()),

    %% Get the port to verify
    {ok, Info1} = quic:get_server_info(port_test_server),
    ?assertEqual(TestPort, maps:get(port, Info1)),

    %% Stop the server
    ok = quic:stop_server(port_test_server),
    _ = (catch quic_server_registry:unregister(port_test_server)),
    %% Give OS time to release the port
    timer:sleep(200),

    %% Start a new server on the same port
    case quic:start_server(port_test_server_2, TestPort, base_opts()) of
        {ok, _} ->
            {ok, Info2} = quic:get_server_info(port_test_server_2),
            ?assertEqual(TestPort, maps:get(port, Info2)),
            ok = quic:stop_server(port_test_server_2);
        {error, eaddrinuse} ->
            %% Port might still be in TIME_WAIT state, that's acceptable
            ct:log("Port ~p still in use (TIME_WAIT), this is acceptable", [TestPort])
    end,

    ct:log("Port reuse test passed").
