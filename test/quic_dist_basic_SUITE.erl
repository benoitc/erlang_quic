%%% -*- erlang -*-
%%%
%%% QUIC Distribution Basic Common Test Suite
%%% Tests basic two-node connectivity
%%%
%%% Both nodes are peers that speak QUIC distribution to each other. The
%%% test node is not one of them, so each case drives node1 with
%%% peer:call/4,5 and collects what it needs on a peer; see
%%% quic_dist_peer for why.
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

%% Run on the peers.
-export([
    spawn_and_hear/1,
    exchange/2,
    exchange_hash/2,
    concurrent_send/2,
    receiver/1,
    hash_receiver/1,
    receive_loop/3
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
    CertDir = filename:join(?config(priv_dir, Config), "certs"),
    {ok, Certs} = quic_dist_peer:generate_certs(CertDir),
    [{certs, Certs} | Config].

end_per_suite(_Config) ->
    ok.

init_per_group(two_node, Config) ->
    case quic_dist_peer:start("quic_ct_basic", 2, ?config(certs, Config)) of
        {ok, [#{peer := Peer1, node := Node1} = P1, #{peer := Peer2, node := Node2} = P2]} ->
            [
                {peers, [P1, P2]},
                {node1, Node1},
                {peer1, Peer1},
                {node2, Node2},
                {peer2, Peer2}
                | Config
            ];
        {error, Reason} ->
            ct:fail({peer_start_failed, Reason})
    end;
init_per_group(_Group, Config) ->
    Config.

end_per_group(two_node, Config) ->
    quic_dist_peer:stop(?config(peers, Config));
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
    {Peer1, Node1, Peer2, Node2} = pair(Config),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    ?assert(lists:member(Node2, peer:call(Peer1, erlang, nodes, []))),
    ?assert(lists:member(Node1, peer:call(Peer2, erlang, nodes, []))).

%% Test net_adm:ping
node_ping_test(Config) ->
    {Peer1, Node1, Peer2, Node2} = pair(Config),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    pong = peer:call(Peer2, net_adm, ping, [Node1]).

%% Test RPC calls
rpc_call_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    ?assertEqual(Node2, peer:call(Peer1, rpc, call, [Node2, erlang, node, []])).

%% Test spawning across nodes: node1 spawns on node2, and the spawned
%% process reports back to node1.
spawn_link_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    ?assertEqual({hello, Node2}, peer:call(Peer1, ?MODULE, spawn_and_hear, [Node2])).

%% Test message passing from node1 to a process on node2
message_passing_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    TestData = {test, 123, <<"binary">>, [list, items, atoms]},
    ?assertEqual({received, TestData}, peer:call(Peer1, ?MODULE, exchange, [Node2, TestData])).

%% Test large message handling: node2 hashes what arrived, so a
%% corrupted or truncated transfer shows as a mismatch.
large_message_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    LargeData = crypto:strong_rand_bytes(1024 * 1024),
    Hash = crypto:hash(sha256, LargeData),
    ?assertEqual(
        {hash, Hash},
        peer:call(Peer1, ?MODULE, exchange_hash, [Node2, LargeData], 60000)
    ).

%% Test concurrent messages
concurrent_messages_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    NumMessages = 100,
    {done, Received} = peer:call(
        Peer1, ?MODULE, concurrent_send, [Node2, NumMessages], 40000
    ),
    %% Order may vary.
    ?assertEqual(lists:seq(1, NumMessages), lists:sort(Received)).

%% Test node disconnection
node_disconnect_test(Config) ->
    {Peer1, _Node1, Peer2, Node2} = pair(Config),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    ?assert(lists:member(Node2, peer:call(Peer1, erlang, nodes, []))),
    true = peer:call(Peer1, erlang, disconnect_node, [Node2]),
    ?assert(wait_until(fun() -> peer:call(Peer1, erlang, nodes, []) =:= [] end)),
    ?assert(wait_until(fun() -> peer:call(Peer2, erlang, nodes, []) =:= [] end)).

%% Test node reconnection
node_reconnect_test(Config) ->
    {Peer1, Node1, Peer2, Node2} = pair(Config),
    %% Disconnected by the previous case.
    ?assertEqual([], peer:call(Peer1, erlang, nodes, [])),
    pong = peer:call(Peer1, net_adm, ping, [Node2]),
    ?assert(lists:member(Node2, peer:call(Peer1, erlang, nodes, []))),
    ?assert(lists:member(Node1, peer:call(Peer2, erlang, nodes, []))),
    ?assertEqual(Node2, peer:call(Peer1, rpc, call, [Node2, erlang, node, []])).

%%====================================================================
%% Run on node1
%%====================================================================

spawn_and_hear(Node2) ->
    Self = self(),
    Pid = spawn(Node2, fun() -> Self ! {hello, node()} end),
    true = is_pid(Pid),
    Node2 = node(Pid),
    receive
        {hello, _} = Hello -> Hello
    after 5000 -> timeout
    end.

exchange(Node2, Data) ->
    Receiver = spawn(Node2, ?MODULE, receiver, [self()]),
    Receiver ! {msg, Data},
    receive
        {received, _} = Got -> Got;
        timeout -> timeout
    after 5000 -> receive_timeout
    end.

exchange_hash(Node2, Data) ->
    Receiver = spawn(Node2, ?MODULE, hash_receiver, [self()]),
    Receiver ! {large, Data},
    receive
        {hash, _} = Got -> Got;
        timeout -> timeout
    after 30000 -> receive_timeout
    end.

concurrent_send(Node2, Count) ->
    Receiver = spawn(Node2, ?MODULE, receive_loop, [self(), Count, []]),
    lists:foreach(fun(N) -> spawn(fun() -> Receiver ! {msg, N} end) end, lists:seq(1, Count)),
    receive
        {done, _} = Done -> Done;
        {partial, _} = Partial -> Partial
    after 30000 -> timeout
    end.

%%====================================================================
%% Run on node2
%%====================================================================

receiver(Parent) ->
    receive
        {msg, Data} -> Parent ! {received, Data}
    after 5000 -> Parent ! timeout
    end.

hash_receiver(Parent) ->
    receive
        {large, Data} -> Parent ! {hash, crypto:hash(sha256, Data)}
    after 30000 -> Parent ! timeout
    end.

receive_loop(Parent, 0, Acc) ->
    Parent ! {done, Acc};
receive_loop(Parent, N, Acc) ->
    receive
        {msg, Data} -> receive_loop(Parent, N - 1, [Data | Acc])
    after 10000 -> Parent ! {partial, Acc}
    end.

%%====================================================================
%% Helpers
%%====================================================================

pair(Config) ->
    {
        ?config(peer1, Config),
        ?config(node1, Config),
        ?config(peer2, Config),
        ?config(node2, Config)
    }.

%% Disconnection reaches the far side asynchronously.
wait_until(Fun) ->
    wait_until(Fun, 50).

wait_until(_Fun, 0) ->
    false;
wait_until(Fun, Tries) ->
    case Fun() of
        true ->
            true;
        false ->
            timer:sleep(100),
            wait_until(Fun, Tries - 1)
    end.
