%%% -*- erlang -*-
%%%
%%% QUIC Distribution Cluster Common Test Suite
%%% Tests multi-node mesh formation and communication
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_cluster_SUITE).

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
    mesh_formation_test/1,
    mesh_all_pairs_test/1,
    node_failure_test/1,
    node_rejoin_test/1,
    broadcast_test/1,
    ring_message_test/1,
    partition_test/1,
    partition_heal_test/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 10}}].

all() ->
    [{group, five_node}].

groups() ->
    [
        {five_node, [sequence], [
            mesh_formation_test,
            mesh_all_pairs_test,
            node_failure_test,
            node_rejoin_test,
            broadcast_test,
            ring_message_test,
            partition_test,
            partition_heal_test
        ]}
    ].

init_per_suite(Config) ->
    %% Generate test certificates
    PrivDir = proplists:get_value(priv_dir, Config),
    CertDir = filename:join(PrivDir, "certs"),
    ok = filelib:ensure_dir(filename:join(CertDir, "dummy")),

    %% Generate certificates (simplified for tests)
    generate_certs(CertDir),

    [{cert_dir, CertDir} | Config].

end_per_suite(Config) ->
    CertDir = proplists:get_value(cert_dir, Config),
    os:cmd("rm -rf " ++ CertDir),
    ok.

init_per_group(five_node, Config) ->
    %% This would start 5 nodes with QUIC distribution
    %% For now, we skip if nodes can't be started
    CertDir = proplists:get_value(cert_dir, Config),

    case start_cluster(5, CertDir) of
        {ok, Nodes} ->
            [{nodes, Nodes} | Config];
        {error, Reason} ->
            {skip, {cluster_start_failed, Reason}}
    end;
init_per_group(_Group, Config) ->
    Config.

end_per_group(five_node, Config) ->
    Nodes = proplists:get_value(nodes, Config, []),
    stop_cluster(Nodes),
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

%% Test that all 5 nodes form a full mesh
mesh_formation_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),

    %% Connect all nodes
    connect_mesh(Nodes),

    %% Each node should see exactly N-1 peers
    ExpectedPeerCount = length(Nodes) - 1,

    lists:foreach(
        fun(Node) ->
            Peers = rpc:call(Node, erlang, nodes, []),
            ?assertEqual(
                ExpectedPeerCount,
                length(Peers),
                {Node, expected, ExpectedPeerCount, got, length(Peers)}
            )
        end,
        Nodes
    ),

    ok.

%% Test that all pairs can communicate
mesh_all_pairs_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),

    %% Test all pairs
    Pairs = [{N1, N2} || N1 <- Nodes, N2 <- Nodes, N1 < N2],

    lists:foreach(
        fun({Node1, Node2}) ->
            %% RPC from Node1 to Node2
            Result = rpc:call(Node1, rpc, call, [Node2, erlang, node, []]),
            ?assertEqual(Node2, Result, {pair, Node1, Node2})
        end,
        Pairs
    ),

    ok.

%% Test behavior when a node fails
node_failure_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),
    [Node1, Node2, Node3, Node4, Node5] = Nodes,

    %% Ensure mesh
    connect_mesh(Nodes),

    %% Kill Node3
    rpc:call(Node3, erlang, halt, [0]),
    timer:sleep(2000),

    %% Remaining nodes should have 3 peers each
    RemainingNodes = [Node1, Node2, Node4, Node5],
    lists:foreach(
        fun(Node) ->
            Peers = rpc:call(Node, erlang, nodes, []),
            ?assertEqual(3, length(Peers), {Node, peers, Peers})
        end,
        RemainingNodes
    ),

    %% Communication should still work
    Node5 = rpc:call(Node1, rpc, call, [Node5, erlang, node, []]),

    ok.

%% Test node rejoin after failure
node_rejoin_test(_Config) ->
    %% This test would restart Node3 and verify it rejoins
    %% For now, we skip as it requires node restart capability
    {skip, requires_node_restart}.

%% Test broadcast to all nodes
broadcast_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),

    %% Ensure mesh
    connect_mesh(Nodes),

    %% Start receivers on all nodes except first
    [_Sender | Receivers] = Nodes,
    Self = self(),

    ReceiverPids = lists:map(
        fun(Node) ->
            rpc:call(Node, erlang, spawn, [
                fun() ->
                    receive
                        {broadcast, Data} ->
                            Self ! {received, Node, Data}
                    after 10000 ->
                        Self ! {timeout, Node}
                    end
                end
            ])
        end,
        Receivers
    ),

    %% Broadcast from sender
    TestData = {test, erlang:system_time()},
    lists:foreach(
        fun(Pid) ->
            Pid ! {broadcast, TestData}
        end,
        ReceiverPids
    ),

    %% Verify all received
    ReceivedFrom = receive_all(length(Receivers), []),
    ?assertEqual(lists:sort(Receivers), lists:sort(ReceivedFrom)),

    ok.

%% Test ring message passing
ring_message_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),

    %% Ensure mesh
    connect_mesh(Nodes),

    %% Start ring processes
    Self = self(),
    % Close the ring
    RingNodes = Nodes ++ [hd(Nodes)],

    %% Create ring
    Pids = lists:foldl(
        fun(Node, Acc) ->
            NextPid =
                case Acc of
                    % Last node points to test process
                    [] -> self;
                    [Prev | _] -> Prev
                end,
            Pid = rpc:call(Node, erlang, spawn, [
                fun() ->
                    ring_process(NextPid, Self)
                end
            ]),
            [Pid | Acc]
        end,
        [],
        lists:reverse(RingNodes)
    ),

    %% Send message through ring
    [FirstPid | _] = Pids,
    FirstPid ! {ring, 0, length(Nodes)},

    %% Wait for message to complete ring
    receive
        {ring_complete, Hops} ->
            ?assertEqual(length(Nodes), Hops)
    after 30000 ->
        ct:fail(ring_timeout)
    end.

%% Test network partition
partition_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),
    [Node1, Node2, Node3, Node4, Node5] = Nodes,

    %% Ensure mesh
    connect_mesh(Nodes),

    %% Partition: disconnect Node1 and Node2 from Node4 and Node5
    %% Node3 stays connected to all (bridge)

    %% For QUIC, we'd need to simulate this at network level
    %% For now, we use disconnect_node

    rpc:call(Node1, erlang, disconnect_node, [Node4]),
    rpc:call(Node1, erlang, disconnect_node, [Node5]),
    rpc:call(Node2, erlang, disconnect_node, [Node4]),
    rpc:call(Node2, erlang, disconnect_node, [Node5]),

    timer:sleep(500),

    %% Verify partition
    %% Node1 should see Node2, Node3
    Peers1 = rpc:call(Node1, erlang, nodes, []),
    ?assert(lists:member(Node2, Peers1)),
    ?assert(lists:member(Node3, Peers1)),
    ?assert(not lists:member(Node4, Peers1)),
    ?assert(not lists:member(Node5, Peers1)),

    ok.

%% Test partition healing
partition_heal_test(Config) ->
    Nodes = proplists:get_value(nodes, Config),
    [Node1, _Node2, _Node3, Node4, _Node5] = Nodes,

    %% Reconnect partitioned nodes
    pong = rpc:call(Node1, net_adm, ping, [Node4]),

    %% Wait for full mesh to reform
    timer:sleep(1000),
    connect_mesh(Nodes),

    %% Verify full connectivity
    ExpectedPeerCount = length(Nodes) - 1,
    lists:foreach(
        fun(Node) ->
            Peers = rpc:call(Node, erlang, nodes, []),
            ?assertEqual(ExpectedPeerCount, length(Peers))
        end,
        Nodes
    ),

    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

generate_certs(CertDir) ->
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s/key.pem -out ~s/cert.pem "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [CertDir, CertDir]
    ),
    os:cmd(lists:flatten(Cmd)),
    ok.

start_cluster(N, _CertDir) ->
    %% Start N nodes with QUIC distribution
    %% This is simplified - actual implementation would use peer module or docker
    BasePort = 14430,

    _Nodes = lists:map(
        fun(I) ->
            Name = list_to_atom("cluster_node" ++ integer_to_list(I)),
            Port = BasePort + I,
            {Name, Port}
        end,
        lists:seq(1, N)
    ),

    %% For now, return skip as we can't actually start nodes in CT
    {error, not_implemented}.

stop_cluster(Nodes) ->
    lists:foreach(
        fun(Node) ->
            catch rpc:call(Node, erlang, halt, [0])
        end,
        Nodes
    ).

connect_mesh([]) ->
    ok;
connect_mesh([_]) ->
    ok;
connect_mesh([Node | Rest]) ->
    lists:foreach(
        fun(OtherNode) ->
            rpc:call(Node, net_adm, ping, [OtherNode])
        end,
        Rest
    ),
    connect_mesh(Rest).

receive_all(0, Acc) ->
    Acc;
receive_all(N, Acc) ->
    receive
        {received, Node, _Data} ->
            receive_all(N - 1, [Node | Acc]);
        {timeout, Node} ->
            ct:fail({timeout, Node})
    after 10000 ->
        ct:fail({receive_all_timeout, got, Acc})
    end.

ring_process(self, Parent) ->
    receive
        {ring, Hops, _Max} ->
            Parent ! {ring_complete, Hops + 1}
    end;
ring_process(NextPid, Parent) ->
    receive
        {ring, Hops, Max} when Hops < Max ->
            NextPid ! {ring, Hops + 1, Max};
        {ring, Hops, _Max} ->
            Parent ! {ring_complete, Hops}
    end.
