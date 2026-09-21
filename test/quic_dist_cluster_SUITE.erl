%%% -*- erlang -*-
%%%
%%% QUIC Distribution Cluster Common Test Suite
%%% Tests multi-node mesh formation and communication
%%%
%%% Five peers that speak QUIC distribution to each other. The test node
%%% is not one of them, so each case drives the peers with peer:call/4,5
%%% and collects what it needs on a peer; see quic_dist_peer for why.
%%%
%%% The cases run in sequence and share the cluster. node_failure_test
%%% brings a node down and node_rejoin_test brings it back under the same
%%% name and port, so every later case sees all five again. The current
%%% peers live in a persistent_term, since a restarted node is a new peer
%%% and Common Test hands each case the group's config unchanged.
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

%% Run on the peers.
-export([broadcast/2, broadcast_receiver/2, ring/1, ring_process/2]).

-define(SIZE, 5).
-define(PEERS, {?MODULE, peers}).

%% global keeps the nodes fully meshed and, since OTP 25, disconnects
%% nodes to undo a partition that overlaps, so the bridged partition
%% below would be rearranged before it could be looked at. The cases
%% build the topology they assert on with explicit pings instead.
-define(NO_MESH, ["-connect_all", "false"]).

%% An abrupt crash sends nothing, so the survivors only learn of it when
%% the connection goes quiet: measured at about 16 s here. Room for a
%% loaded runner, while a node that is never dropped still fails.
-define(FAILURE_NOTICE_MS, 45000).

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
    CertDir = filename:join(?config(priv_dir, Config), "certs"),
    {ok, Certs} = quic_dist_peer:generate_certs(CertDir),
    [{certs, Certs} | Config].

end_per_suite(_Config) ->
    ok.

init_per_group(five_node, Config) ->
    case quic_dist_peer:start("quic_ct_cluster", ?SIZE, ?config(certs, Config), ?NO_MESH) of
        {ok, Peers} ->
            persistent_term:put(?PEERS, Peers),
            Config;
        {error, Reason} ->
            ct:fail({cluster_start_failed, Reason})
    end;
init_per_group(_Group, Config) ->
    Config.

end_per_group(five_node, _Config) ->
    quic_dist_peer:stop(persistent_term:get(?PEERS, [])),
    _ = persistent_term:erase(?PEERS),
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
mesh_formation_test(_Config) ->
    Peers = peers(),
    connect_mesh(Peers),
    assert_full_mesh(Peers).

%% Test that all pairs can communicate
mesh_all_pairs_test(_Config) ->
    Peers = peers(),
    lists:foreach(
        fun({#{peer := From, node := A}, #{node := B}}) ->
            ?assertEqual(B, peer:call(From, rpc, call, [B, erlang, node, []]), {pair, A, B})
        end,
        [{P, Q} || P <- Peers, Q <- Peers, P =/= Q]
    ).

%% Test behavior when a node fails: the others drop it, and keep working.
node_failure_test(_Config) ->
    Peers = peers(),
    [P1, P2, #{peer := Peer3, node := Node3}, P4, #{node := Node5}] = Peers,
    connect_mesh(Peers),
    ok = peer:cast(Peer3, erlang, halt, [0]),
    Survivors = [P1, P2, P4, lists:last(Peers)],
    lists:foreach(
        fun(#{peer := Peer, node := Node}) ->
            ?assert(
                wait_until(
                    fun() -> not lists:member(Node3, peer:call(Peer, erlang, nodes, [])) end,
                    ?FAILURE_NOTICE_MS
                ),
                {Node, still_sees, Node3}
            ),
            ?assertEqual(3, length(peer:call(Peer, erlang, nodes, [])), Node)
        end,
        Survivors
    ),
    #{peer := Peer1} = P1,
    ?assertEqual(Node5, peer:call(Peer1, rpc, call, [Node5, erlang, node, []])).

%% Test node rejoin after failure: the node comes back under its old name
%% and port, and the mesh closes over it again.
node_rejoin_test(Config) ->
    Peers = peers(),
    Dead = lists:nth(3, Peers),
    quic_dist_peer:stop_one(Dead),
    {ok, Back} = quic_dist_peer:restart(Dead, Peers, ?config(certs, Config)),
    Rejoined = [
        case P of
            Dead -> Back;
            _ -> P
        end
     || P <- Peers
    ],
    persistent_term:put(?PEERS, Rejoined),
    connect_mesh(Rejoined),
    assert_full_mesh(Rejoined).

%% Test broadcast to all nodes
broadcast_test(_Config) ->
    [#{peer := Sender} | Receivers] = peers(),
    ReceiverNodes = [N || #{node := N} <- Receivers],
    Heard = peer:call(Sender, ?MODULE, broadcast, [ReceiverNodes, {test, 42}], 30000),
    ?assertEqual(lists:sort(ReceiverNodes), lists:sort(Heard)).

%% Test ring message passing
ring_message_test(_Config) ->
    [#{peer := Start} | _] = Peers = peers(),
    Nodes = [N || #{node := N} <- Peers],
    ?assertEqual({ring_complete, ?SIZE}, peer:call(Start, ?MODULE, ring, [Nodes], 30000)).

%% Test network partition: node1 and node2 drop node4 and node5, node3
%% stays in touch with all of them. Both sides of each cut have to see it.
partition_test(_Config) ->
    Peers = peers(),
    [#{peer := Peer1, node := Node1}, #{peer := Peer2, node := Node2}, #{node := Node3}, P4, P5] =
        Peers,
    #{peer := Peer4, node := Node4} = P4,
    #{node := Node5} = P5,
    connect_mesh(Peers),
    lists:foreach(
        fun({Peer, Far}) -> true = peer:call(Peer, erlang, disconnect_node, [Far]) end,
        [{Peer1, Node4}, {Peer1, Node5}, {Peer2, Node4}, {Peer2, Node5}]
    ),
    ?assert(wait_until(fun() -> sees(Peer1, [Node2, Node3], [Node4, Node5]) end, 5000)),
    ?assert(wait_until(fun() -> sees(Peer4, [Node3, Node5], [Node1, Node2]) end, 5000)).

%% Test partition healing
partition_heal_test(_Config) ->
    Peers = peers(),
    connect_mesh(Peers),
    assert_full_mesh(Peers).

%%====================================================================
%% Run on node1
%%====================================================================

broadcast(Nodes, Data) ->
    Self = self(),
    Pids = [spawn(N, ?MODULE, broadcast_receiver, [Self, N]) || N <- Nodes],
    lists:foreach(fun(Pid) -> Pid ! {broadcast, Data} end, Pids),
    collect(length(Nodes), []).

collect(0, Acc) ->
    Acc;
collect(N, Acc) ->
    receive
        {received, Node} -> collect(N - 1, [Node | Acc])
    after 10000 -> Acc
    end.

%% The token visits every node once and comes back here.
ring(Nodes) ->
    Self = self(),
    First = lists:foldl(
        fun(Node, Next) -> spawn(Node, ?MODULE, ring_process, [Next, Self]) end,
        Self,
        lists:reverse(Nodes)
    ),
    First ! {ring, 0},
    receive
        {ring, Hops} -> {ring_complete, Hops}
    after 20000 -> ring_timeout
    end.

%%====================================================================
%% Run on the other nodes
%%====================================================================

broadcast_receiver(Parent, Node) ->
    receive
        {broadcast, _Data} -> Parent ! {received, Node}
    after 10000 -> ok
    end.

ring_process(Next, _Parent) ->
    receive
        {ring, Hops} -> Next ! {ring, Hops + 1}
    after 20000 -> ok
    end.

%%====================================================================
%% Helpers
%%====================================================================

peers() ->
    persistent_term:get(?PEERS).

connect_mesh(Peers) ->
    lists:foreach(
        fun({#{peer := From}, #{node := To}}) ->
            pong = peer:call(From, net_adm, ping, [To])
        end,
        [{P, Q} || P <- Peers, Q <- Peers, P < Q]
    ).

assert_full_mesh(Peers) ->
    Expected = length(Peers) - 1,
    lists:foreach(
        fun(#{peer := Peer, node := Node}) ->
            ?assert(
                wait_until(
                    fun() -> length(peer:call(Peer, erlang, nodes, [])) =:= Expected end, 5000
                ),
                {Node, sees, peer:call(Peer, erlang, nodes, [])}
            )
        end,
        Peers
    ).

sees(Peer, Present, Absent) ->
    Nodes = peer:call(Peer, erlang, nodes, []),
    lists:all(fun(N) -> lists:member(N, Nodes) end, Present) andalso
        not lists:any(fun(N) -> lists:member(N, Nodes) end, Absent).

wait_until(Fun, BudgetMs) when BudgetMs =< 0 ->
    Fun();
wait_until(Fun, BudgetMs) ->
    case Fun() of
        true ->
            true;
        false ->
            timer:sleep(250),
            wait_until(Fun, BudgetMs - 250)
    end.
