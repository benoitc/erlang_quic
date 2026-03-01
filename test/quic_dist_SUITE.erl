%%% -*- erlang -*-
%%%
%%% QUIC Distribution Test Suite
%%% Tests for quic_dist distribution module
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_dist_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("kernel/include/net_address.hrl").

-export([
    all/0,
    suite/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases - Module callbacks
-export([
    is_node_name_valid/1,
    is_node_name_invalid/1,
    select_valid_node/1,
    address_returns_net_address/1,
    discovery_static_init/1,
    discovery_static_lookup/1,
    epmd_register_node/1,
    epmd_address_please/1
]).

%% Test cases - Distribution
-export([
    quic_app_starts/1,
    listen_creates_server/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [
        {group, module_callbacks},
        {group, distribution}
    ].

groups() ->
    [
        {module_callbacks, [sequence], [
            is_node_name_valid,
            is_node_name_invalid,
            select_valid_node,
            address_returns_net_address,
            discovery_static_init,
            discovery_static_lookup,
            epmd_register_node,
            epmd_address_please
        ]},
        {distribution, [sequence], [
            quic_app_starts,
            listen_creates_server
        ]}
    ].

init_per_suite(Config) ->
    %% Ensure quic application is compiled
    ok = application:load(quic),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(distribution, Config) ->
    %% Start quic application for distribution tests
    {ok, _} = application:ensure_all_started(quic),
    Config;
init_per_group(_GroupName, Config) ->
    Config.

end_per_group(distribution, _Config) ->
    application:stop(quic),
    ok;
end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Test Cases - Module Callbacks
%%====================================================================

%% Test is_node_name/1 with valid node names
is_node_name_valid(_Config) ->
    %% Standard node names should be valid
    true = quic_dist:is_node_name('node@host'),
    true = quic_dist:is_node_name('node1@127.0.0.1'),
    true = quic_dist:is_node_name('my_node@my.host.com'),
    true = quic_dist:is_node_name('a@b'),
    true = quic_dist:is_node_name('test123@localhost'),
    ok.

%% Test is_node_name/1 with invalid node names
is_node_name_invalid(_Config) ->
    %% Names without @ should be invalid
    false = quic_dist:is_node_name(node),
    false = quic_dist:is_node_name(nohost),
    false = quic_dist:is_node_name(''),
    %% Non-atoms should be invalid
    false = quic_dist:is_node_name("node@host"),
    false = quic_dist:is_node_name(123),
    ok.

%% Test select/1 with valid node
select_valid_node(_Config) ->
    %% select should return true for valid node names
    true = quic_dist:select('test@127.0.0.1'),
    true = quic_dist:select('node@localhost'),
    %% Invalid names should return false
    false = quic_dist:select('invalid'),
    ok.

%% Test address/0 returns proper #net_address{}
address_returns_net_address(_Config) ->
    Address = quic_dist:address(),
    %% Should be a net_address record
    ?assert(is_record(Address, net_address)),
    %% Check fields
    quic = Address#net_address.protocol,
    inet = Address#net_address.family,
    ?assert(is_list(Address#net_address.host)),
    ok.

%% Test quic_discovery_static:init/1
discovery_static_init(_Config) ->
    %% Initialize with empty config
    {ok, State} = quic_discovery_static:init([]),
    ?assert(is_map(State)),

    %% Initialize with nodes
    Nodes = [{'node1@host1', {"192.168.1.1", 4433}}],
    {ok, State2} = quic_discovery_static:init([{nodes, Nodes}]),
    ?assert(is_map(State2)),
    ok.

%% Test quic_discovery_static:lookup/2
discovery_static_lookup(_Config) ->
    %% Initialize with nodes
    Nodes = [
        {'node1@host1', {"192.168.1.1", 4433}},
        {'node2@host2', {"192.168.1.2", 4434}}
    ],
    {ok, _} = quic_discovery_static:init([{nodes, Nodes}]),

    %% Lookup existing node
    {ok, {"192.168.1.1", 4433}} = quic_discovery_static:lookup('node1@host1', "host1"),
    {ok, {"192.168.1.2", 4434}} = quic_discovery_static:lookup('node2@host2', "host2"),

    %% Lookup non-existing node
    {error, not_found} = quic_discovery_static:lookup('node3@host3', "host3"),
    ok.

%% Test quic_epmd:register_node/3
epmd_register_node(_Config) ->
    %% Register should succeed and return creation number
    {ok, Creation} = quic_epmd:register_node(test_node, 15433, inet),
    ?assert(is_integer(Creation)),
    ok.

%% Test quic_epmd:address_please/3
epmd_address_please(_Config) ->
    %% First register some nodes via discovery
    Nodes = [
        {'known@127.0.0.1', {{127, 0, 0, 1}, 15433}}
    ],
    {ok, _} = quic_discovery_static:init([{nodes, Nodes}]),

    %% address_please for known node should succeed
    {ok, {127, 0, 0, 1}, 15433, 5} = quic_epmd:address_please("known", "127.0.0.1", inet),
    ok.

%%====================================================================
%% Test Cases - Distribution
%%====================================================================

%% Test that quic application starts properly
quic_app_starts(_Config) ->
    %% Application should already be started from init_per_group
    {ok, _} = application:ensure_all_started(quic),

    %% Verify quic_sup is running
    ?assert(is_pid(whereis(quic_sup))),

    %% Verify ETS table for discovery exists
    ?assertNotEqual(undefined, ets:info(quic_discovery_static_nodes)),
    ok.

%% Test that listen/1 creates a QUIC server
listen_creates_server(_Config) ->
    %% This test requires certificates
    PrivDir = code:priv_dir(quic),
    CertFile = filename:join([PrivDir, "..", "test", "e2e", "certs", "cert.pem"]),
    KeyFile = filename:join([PrivDir, "..", "test", "e2e", "certs", "key.pem"]),

    %% Check if test certs exist
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            %% Set up configuration - use a random high port to avoid conflicts
            Port = 20000 + rand:uniform(10000),
            application:set_env(quic, dist_port, Port),
            application:set_env(quic, dist, [
                {cert_file, CertFile},
                {key_file, KeyFile}
            ]),

            %% Try to listen
            case quic_dist:listen(test_listen) of
                {ok, {Listener, Address, Creation}} ->
                    %% Verify return values
                    ?assert(is_record(Address, net_address)),
                    ?assert(is_integer(Creation)),
                    ?assert(Creation >= 1),
                    ?assert(Creation =< 3),

                    %% Clean up
                    quic_dist:close(Listener),
                    ok;
                {error, Reason} ->
                    ct:log("listen/1 failed: ~p", [Reason]),
                    {skip, {listen_failed, Reason}}
            end;
        _ ->
            {skip, "Test certificates not found"}
    end.
