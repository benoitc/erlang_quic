%%% -*- erlang -*-
%%%
%%% QUIC Distribution Basic Common Test Suite
%%% Tests basic two-node connectivity
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_basic_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% CT callbacks
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

%% Test cases
-export([
    node_connect_test/1,
    node_ping_test/1,
    rpc_call_test/1,
    spawn_link_test/1,
    message_passing_test/1,
    large_message_test/1,
    concurrent_messages_test/1,
    node_disconnect_test/1,
    node_reconnect_test/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [{group, two_node}].

groups() ->
    [
        {two_node, [sequence], [
            node_connect_test,
            node_ping_test,
            rpc_call_test,
            spawn_link_test,
            message_passing_test,
            large_message_test,
            concurrent_messages_test,
            node_disconnect_test,
            node_reconnect_test
        ]}
    ].

init_per_suite(Config) ->
    %% Generate test certificates
    {ok, CertDir} = generate_test_certs(Config),

    %% Configure QUIC distribution
    DistConfig = [
        {cert_file, filename:join(CertDir, "cert.pem")},
        {key_file, filename:join(CertDir, "key.pem")},
        {verify, verify_none},
        {discovery_module, quic_discovery_static}
    ],

    application:set_env(quic, dist, DistConfig),

    [{cert_dir, CertDir}, {dist_config, DistConfig} | Config].

end_per_suite(Config) ->
    %% Clean up test certificates
    CertDir = proplists:get_value(cert_dir, Config),
    os:cmd("rm -rf " ++ CertDir),
    ok.

init_per_group(two_node, Config) ->
    %% Check if we can start peer nodes
    case code:which(peer) of
        non_existing ->
            {skip, peer_module_not_available};
        _ ->
            CertDir = proplists:get_value(cert_dir, Config),
            case start_peer_nodes(CertDir, Config) of
                {ok, Node1, Peer1, Node2, Peer2} ->
                    [
                        {node1, Node1},
                        {peer1, Peer1},
                        {node2, Node2},
                        {peer2, Peer2}
                        | Config
                    ];
                {error, Reason} ->
                    {skip, {peer_start_failed, Reason}}
            end
    end;
init_per_group(_Group, Config) ->
    Config.

end_per_group(two_node, Config) ->
    %% Stop peer nodes
    Peer1 = proplists:get_value(peer1, Config),
    Peer2 = proplists:get_value(peer2, Config),

    catch peer:stop(Peer1),
    catch peer:stop(Peer2),
    ok;
end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Test Cases
%%====================================================================

%% Test basic node connection
node_connect_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Connect Node1 to Node2
    pong = rpc:call(Node1, net_adm, ping, [Node2]),

    %% Verify connection
    Nodes1 = rpc:call(Node1, erlang, nodes, []),
    Nodes2 = rpc:call(Node2, erlang, nodes, []),

    ?assert(lists:member(Node2, Nodes1)),
    ?assert(lists:member(Node1, Nodes2)),

    ok.

%% Test net_adm:ping
node_ping_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Ping should succeed
    pong = rpc:call(Node1, net_adm, ping, [Node2]),
    pong = rpc:call(Node2, net_adm, ping, [Node1]),

    ok.

%% Test RPC calls
rpc_call_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Ensure connected
    pong = rpc:call(Node1, net_adm, ping, [Node2]),

    %% Simple RPC call
    Node2 = rpc:call(Node1, rpc, call, [Node2, erlang, node, []]),

    ok.

%% Test spawn_link across nodes
spawn_link_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Ensure connected
    pong = rpc:call(Node1, net_adm, ping, [Node2]),

    %% Spawn a process on Node2 from Node1
    Self = self(),
    Pid = rpc:call(Node1, erlang, spawn, [
        Node2,
        fun() ->
            Self ! {hello, node()}
        end
    ]),

    ?assert(is_pid(Pid)),
    ?assertEqual(Node2, node(Pid)),

    %% Wait for message
    receive
        {hello, Node2} -> ok
    after 5000 ->
        ct:fail(spawn_link_timeout)
    end.

%% Test message passing
message_passing_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Ensure connected
    pong = rpc:call(Node1, net_adm, ping, [Node2]),

    %% Start a receiver on Node2
    Self = self(),
    Receiver = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                {msg, Data} ->
                    Self ! {received, Data}
            after 5000 ->
                Self ! timeout
            end
        end
    ]),

    %% Send message from Node1 to Node2
    TestData = {test, 123, <<"binary">>, [list, items, atoms]},
    Receiver ! {msg, TestData},

    %% Verify received
    receive
        {received, TestData} -> ok;
        timeout -> ct:fail(message_timeout)
    after 5000 ->
        ct:fail(receive_timeout)
    end.

%% Test large message handling
large_message_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Ensure connected
    pong = rpc:call(Node1, net_adm, ping, [Node2]),

    %% Create large message (1MB)
    LargeData = crypto:strong_rand_bytes(1024 * 1024),
    Hash = crypto:hash(sha256, LargeData),

    %% Send and verify integrity
    Self = self(),
    Receiver = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                {large, Data} ->
                    RecvHash = crypto:hash(sha256, Data),
                    Self ! {hash, RecvHash}
            after 30000 ->
                Self ! timeout
            end
        end
    ]),

    Receiver ! {large, LargeData},

    receive
        {hash, Hash} -> ok;
        {hash, Other} -> ct:fail({hash_mismatch, Hash, Other});
        timeout -> ct:fail(large_message_timeout)
    after 30000 ->
        ct:fail(receive_timeout)
    end.

%% Test concurrent messages
concurrent_messages_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Ensure connected
    pong = rpc:call(Node1, net_adm, ping, [Node2]),

    %% Start receiver
    Self = self(),
    NumMessages = 100,

    Receiver = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive_loop(Self, NumMessages, [])
        end
    ]),

    %% Send messages concurrently
    lists:foreach(
        fun(N) ->
            spawn(fun() ->
                Receiver ! {msg, N}
            end)
        end,
        lists:seq(1, NumMessages)
    ),

    %% Wait for all messages
    receive
        {done, Received} ->
            ?assertEqual(NumMessages, length(Received)),
            %% Verify all messages received (order may vary)
            Expected = lists:seq(1, NumMessages),
            ?assertEqual(lists:sort(Expected), lists:sort(Received))
    after 30000 ->
        ct:fail(concurrent_messages_timeout)
    end.

%% Test node disconnection
node_disconnect_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Ensure connected
    pong = rpc:call(Node1, net_adm, ping, [Node2]),
    ?assert(lists:member(Node2, rpc:call(Node1, erlang, nodes, []))),

    %% Disconnect
    true = rpc:call(Node1, erlang, disconnect_node, [Node2]),

    %% Verify disconnected
    timer:sleep(100),
    ?assertEqual([], rpc:call(Node1, erlang, nodes, [])),
    ?assertEqual([], rpc:call(Node2, erlang, nodes, [])),

    ok.

%% Test node reconnection
node_reconnect_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Should be disconnected from previous test
    ?assertEqual([], rpc:call(Node1, erlang, nodes, [])),

    %% Reconnect
    pong = rpc:call(Node1, net_adm, ping, [Node2]),

    %% Verify reconnected
    ?assert(lists:member(Node2, rpc:call(Node1, erlang, nodes, []))),
    ?assert(lists:member(Node1, rpc:call(Node2, erlang, nodes, []))),

    %% Verify communication works
    Node2 = rpc:call(Node1, rpc, call, [Node2, erlang, node, []]),

    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

receive_loop(Parent, 0, Acc) ->
    Parent ! {done, Acc};
receive_loop(Parent, N, Acc) ->
    receive
        {msg, Data} ->
            receive_loop(Parent, N - 1, [Data | Acc])
    after 10000 ->
        Parent ! {partial, Acc}
    end.

generate_test_certs(Config) ->
    PrivDir = proplists:get_value(priv_dir, Config),
    CertDir = filename:join(PrivDir, "certs"),
    ok = filelib:ensure_dir(filename:join(CertDir, "dummy")),

    %% Generate self-signed certificate using openssl
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s/key.pem -out ~s/cert.pem "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [CertDir, CertDir]
    ),

    os:cmd(lists:flatten(Cmd)),

    %% Verify files were created
    case
        {
            filelib:is_file(filename:join(CertDir, "cert.pem")),
            filelib:is_file(filename:join(CertDir, "key.pem"))
        }
    of
        {true, true} ->
            {ok, CertDir};
        _ ->
            {error, cert_generation_failed}
    end.

start_peer_nodes(CertDir, Config) ->
    %% Write sys.config for nodes
    _PrivDir = proplists:get_value(priv_dir, Config),

    Node1Name = list_to_atom(
        "quic_ct_node1_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    Node2Name = list_to_atom(
        "quic_ct_node2_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),

    %% Build code path
    CodePath = code:get_path(),

    %% Common peer options
    PeerOpts = fun(Name, Port) ->
        #{
            name => Name,
            host => "127.0.0.1",
            args => [
                "-proto_dist",
                "quic",
                "-epmd_module",
                "quic_epmd",
                "-start_epmd",
                "false",
                "-quic_dist_port",
                integer_to_list(Port),
                "-setcookie",
                atom_to_list(erlang:get_cookie()),
                "-pa"
                | lists:flatmap(fun(P) -> [P] end, CodePath)
            ],
            connection => standard_io
        }
    end,

    %% Start peer nodes
    try
        {ok, Peer1, Node1} = peer:start_link(PeerOpts(Node1Name, 14433)),
        {ok, Peer2, Node2} = peer:start_link(PeerOpts(Node2Name, 14434)),

        %% Configure QUIC distribution on nodes
        Nodes = [
            {Node1, {"127.0.0.1", 14433}},
            {Node2, {"127.0.0.1", 14434}}
        ],

        DistConfig = [
            {cert_file, filename:join(CertDir, "cert.pem")},
            {key_file, filename:join(CertDir, "key.pem")},
            {verify, verify_none},
            {discovery_module, quic_discovery_static},
            {nodes, Nodes}
        ],

        %% Apply configuration
        ok = rpc:call(Node1, application, set_env, [quic, dist, DistConfig]),
        ok = rpc:call(Node2, application, set_env, [quic, dist, DistConfig]),

        %% Start quic application
        {ok, _} = rpc:call(Node1, application, ensure_all_started, [quic]),
        {ok, _} = rpc:call(Node2, application, ensure_all_started, [quic]),

        %% Initialize discovery
        {ok, _} = rpc:call(Node1, quic_discovery_static, init, [[{nodes, Nodes}]]),
        {ok, _} = rpc:call(Node2, quic_discovery_static, init, [[{nodes, Nodes}]]),

        {ok, Node1, Peer1, Node2, Peer2}
    catch
        _:Reason ->
            {error, Reason}
    end.
