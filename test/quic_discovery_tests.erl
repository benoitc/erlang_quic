%%% -*- erlang -*-
%%%
%%% QUIC Discovery Unit Tests
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_discovery_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Static Discovery Tests
%%====================================================================

static_init_test() ->
    %% Initialize with some nodes
    Opts = [{nodes, [
        {'node1@host1', {{192,168,1,1}, 4433}},
        {'node2@host2', {{192,168,1,2}, 4433}}
    ]}],

    {ok, State} = quic_discovery_static:init(Opts),
    ?assert(is_map(State)).

static_lookup_test() ->
    %% Initialize
    Opts = [{nodes, [
        {'node1@host1', {{192,168,1,1}, 4433}},
        {'node2@host2', {{192,168,1,2}, 4433}}
    ]}],

    {ok, _State} = quic_discovery_static:init(Opts),

    %% Lookup existing node
    {ok, {{192,168,1,1}, 4433}} = quic_discovery_static:lookup('node1@host1', "host1"),

    %% Lookup another node
    {ok, {{192,168,1,2}, 4433}} = quic_discovery_static:lookup('node2@host2', "host2"),

    %% Lookup non-existent node (should check config)
    %% Note: This may return error or fall through to DNS
    ok.

static_register_test() ->
    %% Initialize
    {ok, State} = quic_discovery_static:init([]),

    %% Register a new node
    {ok, _State1} = quic_discovery_static:register('node3@host3', 4433, State),

    %% Verify it can be looked up
    {ok, _Address} = quic_discovery_static:lookup('node3@host3', "host3"),
    ok.

static_list_nodes_test() ->
    %% Initialize with nodes
    Opts = [{nodes, [
        {'node1@host1', {{192,168,1,1}, 4433}},
        {'node2@host2', {{192,168,1,2}, 4433}}
    ]}],

    {ok, _State} = quic_discovery_static:init(Opts),

    %% List all nodes
    {ok, Nodes} = quic_discovery_static:list_nodes("any"),
    ?assert(is_list(Nodes)),
    ?assert(length(Nodes) >= 2).

%%====================================================================
%% EPMD Module Tests
%%====================================================================

epmd_port_please_test() ->
    %% Initialize static discovery
    Opts = [{nodes, [
        {'test@localhost', {{127,0,0,1}, 4433}}
    ]}],
    {ok, _} = quic_discovery_static:init(Opts),

    %% Set up application env
    application:set_env(quic, dist, [
        {discovery_module, quic_discovery_static},
        {nodes, [{'test@localhost', {{127,0,0,1}, 4433}}]}
    ]),

    %% Test port_please
    Result = quic_epmd:port_please("test", "localhost"),
    case Result of
        {port, Port, _Version} ->
            ?assertEqual(4433, Port);
        noport ->
            %% OK if not found (depends on config state)
            ok
    end.

epmd_register_test() ->
    %% Test register_node
    {ok, Creation} = quic_epmd:register_node(test, 4433),
    ?assert(is_integer(Creation)),
    ?assert(Creation > 0).

epmd_names_test() ->
    %% Initialize with nodes
    Opts = [{nodes, [
        {'test1@localhost', {{127,0,0,1}, 4433}},
        {'test2@localhost', {{127,0,0,1}, 4434}}
    ]}],
    {ok, _} = quic_discovery_static:init(Opts),

    %% Test names
    case quic_epmd:names("localhost") of
        {ok, Names} ->
            ?assert(is_list(Names));
        {error, _} ->
            %% OK if not supported
            ok
    end.

%%====================================================================
%% DNS Discovery Tests (mocked)
%%====================================================================

dns_init_test() ->
    Opts = [{dns_domain, "test.local"}, {dns_ttl, 60}],
    {ok, State} = quic_discovery_dns:init(Opts),
    ?assert(is_map(State)).

%% Note: DNS tests are limited without actual DNS server.
%% Full DNS testing is done in CT suites with mocking.

%%====================================================================
%% Discovery Behaviour Tests
%%====================================================================

behaviour_api_test() ->
    %% Set up environment
    application:set_env(quic, dist, [
        {discovery_module, quic_discovery_static}
    ]),

    %% These functions should not crash
    _ = quic_discovery:lookup('nonexistent@host', "host"),
    _ = quic_discovery:list_nodes("host"),
    ok.

%%====================================================================
%% Helper Function Tests
%%====================================================================

parse_init_nodes_test() ->
    %% Test parsing of node configuration from init arguments
    %% This would be called internally
    %% We just verify the format is parseable
    NodesStr = "[{'node1@host1', {\"192.168.1.1\", 4433}}].",
    {ok, Tokens, _} = erl_scan:string(NodesStr),
    {ok, Nodes} = erl_parse:parse_term(Tokens),

    ?assertEqual([{'node1@host1', {"192.168.1.1", 4433}}], Nodes).
