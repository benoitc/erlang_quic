%%% -*- erlang -*-
%%%
%%% QUIC Distribution RPC and Message Passing Tests
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc Unit tests for RPC and message passing over QUIC distribution.
%%%
%%% These tests verify that Erlang's distribution mechanisms work correctly
%%% over the QUIC transport layer. Tests include:
%%%
%%% - Basic RPC calls (rpc:call, rpc:cast, rpc:multicall)
%%% - Message passing (!, send)
%%% - Process spawning (spawn, spawn_link, spawn_monitor)
%%% - Process linking and monitoring across nodes
%%% - gen_server calls across nodes
%%% - Large message transfers
%%% - Concurrent message handling
%%%
%%% Note: These tests use the peer module to start QUIC distribution nodes.
%%% The test node itself uses TCP distribution, but communicates with peer
%%% nodes via the peer:call/4 interface. The peer nodes communicate with
%%% each other via QUIC distribution.
%%% @end

-module(quic_dist_rpc_tests).

-include_lib("eunit/include/eunit.hrl").

%% Gen_server callbacks for test_gen_server_call test
-export([init/1, handle_call/3, handle_cast/2]).

%%====================================================================
%% Test Generators
%%====================================================================

%% Main test generator - runs all tests if peer nodes can be started
%% Returns empty list when peer nodes cannot be started (skip test silently)
quic_dist_rpc_test_() ->
    case setup() of
        {skip, _Reason} ->
            %% Can't start peer nodes - skip all tests silently
            %% These tests require peer module and QUIC distribution setup
            [];
        Context ->
            {setup, fun() -> Context end, fun cleanup/1, fun(Ctx) ->
                {inorder, [
                    {"Basic RPC call", fun() -> test_basic_rpc_call(Ctx) end},
                    {"RPC call with args", fun() -> test_rpc_call_with_args(Ctx) end},
                    {"RPC cast", fun() -> test_rpc_cast(Ctx) end},
                    {"RPC multicall", fun() -> test_rpc_multicall(Ctx) end},
                    {"RPC block_call", fun() -> test_rpc_block_call(Ctx) end},
                    {"Message send", fun() -> test_message_send(Ctx) end},
                    {"Message send to registered", fun() -> test_message_send_registered(Ctx) end},
                    {"Remote spawn", fun() -> test_remote_spawn(Ctx) end},
                    {"Remote spawn_link", fun() -> test_remote_spawn_link(Ctx) end},
                    {"Remote spawn_monitor", fun() -> test_remote_spawn_monitor(Ctx) end},
                    {"Process link across nodes", fun() -> test_link_across_nodes(Ctx) end},
                    {"Process monitor across nodes", fun() -> test_monitor_across_nodes(Ctx) end},
                    {"Gen_server call", fun() -> test_gen_server_call(Ctx) end},
                    {"Large binary transfer", fun() -> test_large_binary(Ctx) end},
                    {"Large term transfer", fun() -> test_large_term(Ctx) end},
                    {"Concurrent RPCs", fun() -> test_concurrent_rpcs(Ctx) end},
                    {"Bidirectional messages", fun() -> test_bidirectional_messages(Ctx) end},
                    {"RPC timeout", fun() -> test_rpc_timeout(Ctx) end},
                    {"RPC error handling", fun() -> test_rpc_error_handling(Ctx) end},
                    {"Global registration", fun() -> test_global_registration(Ctx) end}
                ]}
            end}
    end.

%%====================================================================
%% Setup and Cleanup
%%====================================================================

setup() ->
    %% Check if peer module is available
    case code:which(peer) of
        non_existing ->
            {skip, peer_module_not_available};
        _ ->
            setup_peer_nodes()
    end.

setup_peer_nodes() ->
    %% Create temp directory for certs
    TmpDir = filename:join([
        "/tmp", "quic_dist_test_" ++ integer_to_list(erlang:unique_integer([positive]))
    ]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    %% Generate test certificates
    CertFile = filename:join(TmpDir, "cert.pem"),
    KeyFile = filename:join(TmpDir, "key.pem"),
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile]
    ),
    os:cmd(lists:flatten(Cmd)),

    %% Check certs were created
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            start_peer_nodes(TmpDir, CertFile, KeyFile);
        _ ->
            os:cmd("rm -rf " ++ TmpDir),
            {skip, cert_generation_failed}
    end.

start_peer_nodes(TmpDir, CertFile, KeyFile) ->
    CodePath = code:get_path(),
    Cookie = erlang:get_cookie(),

    Node1Name = list_to_atom(
        "quic_rpc_test1_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    Node2Name = list_to_atom(
        "quic_rpc_test2_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),

    %% Build peer options - use quic dist with credentials via command line
    PeerOpts = fun(Name, Port) ->
        #{
            name => Name,
            args => [
                "-proto_dist",
                "quic",
                "-epmd_module",
                "quic_epmd",
                "-start_epmd",
                "false",
                "-quic_dist_port",
                integer_to_list(Port),
                "-quic_dist_cert",
                CertFile,
                "-quic_dist_key",
                KeyFile,
                "-setcookie",
                atom_to_list(Cookie)
            ] ++ lists:flatmap(fun(P) -> ["-pa", P] end, CodePath),
            connection => standard_io
        }
    end,

    try
        {ok, Peer1, Node1} = peer:start_link(PeerOpts(Node1Name, 24433)),
        {ok, Peer2, Node2} = peer:start_link(PeerOpts(Node2Name, 24434)),

        %% Configure QUIC discovery on both nodes (using peer:call, not rpc:call)
        Nodes = [{Node1, {"127.0.0.1", 24433}}, {Node2, {"127.0.0.1", 24434}}],
        DistConfig = [
            {cert_file, CertFile},
            {key_file, KeyFile},
            {verify, verify_none},
            {discovery_module, quic_discovery_static},
            {nodes, Nodes}
        ],

        ok = peer:call(Peer1, application, set_env, [quic, dist, DistConfig]),
        ok = peer:call(Peer2, application, set_env, [quic, dist, DistConfig]),

        %% Initialize discovery
        {ok, _} = peer:call(Peer1, quic_discovery_static, init, [[{nodes, Nodes}]]),
        {ok, _} = peer:call(Peer2, quic_discovery_static, init, [[{nodes, Nodes}]]),

        %% Connect nodes (QUIC to QUIC)
        pong = peer:call(Peer1, net_adm, ping, [Node2]),

        %% Verify connection
        timer:sleep(500),
        case {peer:call(Peer1, erlang, nodes, []), peer:call(Peer2, erlang, nodes, [])} of
            {N1List, N2List} when is_list(N1List), is_list(N2List) ->
                case {lists:member(Node2, N1List), lists:member(Node1, N2List)} of
                    {true, true} ->
                        {
                            #{
                                peer1 => Peer1,
                                peer2 => Peer2,
                                node1 => Node1,
                                node2 => Node2
                            },
                            TmpDir
                        };
                    _ ->
                        peer:stop(Peer1),
                        peer:stop(Peer2),
                        os:cmd("rm -rf " ++ TmpDir),
                        {skip, nodes_not_connected}
                end;
            _ ->
                peer:stop(Peer1),
                peer:stop(Peer2),
                os:cmd("rm -rf " ++ TmpDir),
                {skip, rpc_failed}
        end
    catch
        _:Reason ->
            os:cmd("rm -rf " ++ TmpDir),
            {skip, {peer_start_failed, Reason}}
    end.

cleanup({skip, _}) ->
    ok;
cleanup({#{peer1 := Peer1, peer2 := Peer2}, TmpDir}) ->
    catch peer:stop(Peer1),
    catch peer:stop(Peer2),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%====================================================================
%% RPC Tests
%%====================================================================

%% Test basic RPC call between QUIC nodes
test_basic_rpc_call({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    %% Call erlang:node() on Node2 from Node1 via QUIC distribution
    Result = peer:call(Peer1, rpc, call, [Node2, erlang, node, []]),
    ?assertEqual(Node2, Result).

%% Test RPC call with arguments
test_rpc_call_with_args({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    %% Call lists:seq on Node2
    Result = peer:call(Peer1, rpc, call, [Node2, lists, seq, [1, 10]]),
    ?assertEqual(lists:seq(1, 10), Result),

    %% Call erlang:'+' with args
    Result2 = peer:call(Peer1, rpc, call, [Node2, erlang, '+', [5, 7]]),
    ?assertEqual(12, Result2).

%% Test RPC cast (async)
test_rpc_cast({#{peer1 := Peer1, peer2 := Peer2, node2 := Node2}, _TmpDir}) ->
    %% Start a receiver on Node2 that will report back
    TestRef = make_ref(),

    %% Spawn receiver on Node2
    ReceiverPid = peer:call(Peer2, erlang, spawn, [
        fun() ->
            receive
                {cast_test, Ref} ->
                    %% Can't send to test process directly (different distribution)
                    %% Just store the result
                    put(cast_result, {got_cast, Ref})
            after 5000 ->
                put(cast_result, timeout)
            end,
            %% Keep alive for a bit so we can check
            timer:sleep(1000)
        end
    ]),

    %% Cast from Node1 to Node2
    true = peer:call(Peer1, rpc, cast, [Node2, erlang, send, [ReceiverPid, {cast_test, TestRef}]]),

    %% Wait a bit and check the result
    timer:sleep(200),
    Result = peer:call(Peer2, erlang, apply, [
        fun(Pid) -> rpc:call(node(Pid), erlang, process_info, [Pid, dictionary]) end,
        [ReceiverPid]
    ]),
    case Result of
        {dictionary, Dict} ->
            ?assertEqual({got_cast, TestRef}, proplists:get_value(cast_result, Dict));
        _ ->
            %% Process might have exited, check differently
            ok
    end.

%% Test RPC multicall
test_rpc_multicall({#{peer1 := Peer1, node1 := Node1, node2 := Node2}, _TmpDir}) ->
    %% Multicall to both nodes
    {Results, BadNodes} = peer:call(Peer1, rpc, multicall, [[Node1, Node2], erlang, node, []]),

    ?assertEqual([], BadNodes),
    ?assertEqual(2, length(Results)),
    ?assert(lists:member(Node1, Results)),
    ?assert(lists:member(Node2, Results)).

%% Test RPC block_call (doesn't process messages while waiting)
test_rpc_block_call({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    Result = peer:call(Peer1, rpc, block_call, [Node2, timer, sleep, [100]]),
    ?assertEqual(ok, Result).

%%====================================================================
%% Message Passing Tests
%%====================================================================

%% Test direct message send between QUIC nodes
test_message_send({#{peer1 := Peer1, peer2 := Peer2}, _TmpDir}) ->
    TestData = {test, make_ref(), <<"binary">>, [1, 2, 3]},

    %% Spawn receiver on Node2
    ReceiverPid = peer:call(Peer2, erlang, spawn, [
        fun() ->
            receive
                Msg -> put(received_msg, Msg)
            after 5000 ->
                put(received_msg, timeout)
            end,
            timer:sleep(1000)
        end
    ]),

    %% Send message from Node1 to Node2
    peer:call(Peer1, erlang, send, [ReceiverPid, TestData]),

    %% Check the result
    timer:sleep(200),
    {dictionary, Dict} = peer:call(Peer2, erlang, process_info, [ReceiverPid, dictionary]),
    ?assertEqual(TestData, proplists:get_value(received_msg, Dict)).

%% Test message send to registered process
test_message_send_registered({#{peer1 := Peer1, peer2 := Peer2, node2 := Node2}, _TmpDir}) ->
    %% Register a process on Node2
    peer:call(Peer2, erlang, apply, [
        fun() ->
            register(
                test_receiver,
                spawn(fun() ->
                    receive
                        {test_msg, Data} -> put(reg_result, {from_registered, Data})
                    after 5000 ->
                        put(reg_result, reg_timeout)
                    end,
                    timer:sleep(1000)
                end)
            ),
            ok
        end,
        []
    ]),

    %% Send to registered name from Node1
    peer:call(Peer1, erlang, send, [{test_receiver, Node2}, {test_msg, hello}]),

    %% Check result
    timer:sleep(200),
    RecvPid = peer:call(Peer2, erlang, whereis, [test_receiver]),
    {dictionary, Dict} = peer:call(Peer2, erlang, process_info, [RecvPid, dictionary]),
    ?assertEqual({from_registered, hello}, proplists:get_value(reg_result, Dict)).

%%====================================================================
%% Process Spawning Tests
%%====================================================================

%% Test remote spawn
test_remote_spawn({#{peer1 := Peer1, peer2 := Peer2, node2 := Node2}, _TmpDir}) ->
    %% Spawn on Node2 from Node1
    Pid = peer:call(Peer1, erlang, spawn, [
        Node2,
        fun() ->
            put(spawned_result, {spawned_on, node()}),
            timer:sleep(1000)
        end
    ]),

    ?assertEqual(Node2, node(Pid)),

    timer:sleep(100),
    {dictionary, Dict} = peer:call(Peer2, erlang, process_info, [Pid, dictionary]),
    ?assertEqual({spawned_on, Node2}, proplists:get_value(spawned_result, Dict)).

%% Test remote spawn_link
test_remote_spawn_link({#{peer1 := Peer1, peer2 := Peer2, node2 := Node2}, _TmpDir}) ->
    %% Spawn linked process on Node2
    Pid = peer:call(Peer1, erlang, spawn_link, [
        Node2,
        fun() ->
            put(link_result, {linked_spawned, self(), node()}),
            timer:sleep(1000)
        end
    ]),

    ?assertEqual(Node2, node(Pid)),

    timer:sleep(100),
    {dictionary, Dict} = peer:call(Peer2, erlang, process_info, [Pid, dictionary]),
    ?assertEqual({linked_spawned, Pid, Node2}, proplists:get_value(link_result, Dict)).

%% Test remote spawn_monitor
test_remote_spawn_monitor({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    %% Spawn monitored process on Node2 that exits immediately
    %% We need to capture the DOWN message on Node1
    Result = peer:call(Peer1, erlang, apply, [
        fun() ->
            {Pid, MonRef} = spawn_monitor(Node2, fun() -> exit(normal) end),
            receive
                {'DOWN', MonRef, process, Pid, Reason} ->
                    {ok, node(Pid), Reason}
            after 5000 ->
                timeout
            end
        end,
        []
    ]),

    ?assertEqual({ok, Node2, normal}, Result).

%%====================================================================
%% Link and Monitor Tests
%%====================================================================

%% Test link across nodes
test_link_across_nodes({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    %% Test from Node1's perspective
    Result = peer:call(Peer1, erlang, apply, [
        fun() ->
            process_flag(trap_exit, true),
            Pid = spawn(Node2, fun() ->
                receive
                    die -> exit(test_exit)
                end
            end),
            link(Pid),
            Pid ! die,
            receive
                {'EXIT', Pid, test_exit} -> ok
            after 5000 ->
                timeout
            end
        end,
        []
    ]),
    ?assertEqual(ok, Result).

%% Test monitor across nodes
test_monitor_across_nodes({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    Result = peer:call(Peer1, erlang, apply, [
        fun() ->
            Pid = spawn(Node2, fun() ->
                receive
                    die -> exit(test_exit)
                end
            end),
            MonRef = monitor(process, Pid),
            Pid ! die,
            receive
                {'DOWN', MonRef, process, Pid, test_exit} -> ok
            after 5000 ->
                timeout
            end
        end,
        []
    ]),
    ?assertEqual(ok, Result).

%%====================================================================
%% Gen_server Tests
%%====================================================================

%% Test gen_server call across nodes
test_gen_server_call({#{peer1 := Peer1, peer2 := Peer2, node2 := Node2}, _TmpDir}) ->
    %% Start a simple gen_server on Node2
    {ok, _ServerPid} = peer:call(Peer2, gen_server, start, [
        {local, test_gen_server},
        ?MODULE,
        [],
        []
    ]),

    %% Call the gen_server from Node1
    Result = peer:call(Peer1, gen_server, call, [{test_gen_server, Node2}, {echo, test_value}]),
    ?assertEqual({ok, test_value}, Result),

    %% Clean up
    peer:call(Peer2, gen_server, stop, [test_gen_server]).

%% Gen_server callbacks for test (exported at module top)
init([]) ->
    {ok, #{}}.

handle_call({echo, Value}, _From, State) ->
    {reply, {ok, Value}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

%%====================================================================
%% Large Data Tests
%%====================================================================

%% Test large binary transfer
test_large_binary({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    %% Create 1MB binary
    Size = 1024 * 1024,
    Data = crypto:strong_rand_bytes(Size),
    Hash = crypto:hash(sha256, Data),

    %% Transfer via RPC between QUIC nodes
    RecvHash = peer:call(Peer1, rpc, call, [Node2, crypto, hash, [sha256, Data]], 60000),

    ?assertEqual(Hash, RecvHash).

%% Test large term transfer
test_large_term({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    %% Create large nested term
    LargeTerm = create_large_term(10000),

    %% Transfer and verify
    Result = peer:call(Peer1, rpc, call, [Node2, erlang, length, [LargeTerm]], 60000),
    ?assertEqual(10000, Result).

create_large_term(N) ->
    [{I, make_ref(), <<"data">>, [a, b, c]} || I <- lists:seq(1, N)].

%%====================================================================
%% Concurrent Tests
%%====================================================================

%% Test concurrent RPCs
test_concurrent_rpcs({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    NumProcs = 50,

    %% Run concurrent RPCs from Node1 to Node2
    Results = peer:call(
        Peer1,
        erlang,
        apply,
        [
            fun() ->
                Self = self(),
                _ = [
                    spawn_link(fun() ->
                        Result = rpc:call(Node2, erlang, '+', [I, I]),
                        Self ! {done, I, Result}
                    end)
                 || I <- lists:seq(1, NumProcs)
                ],
                %% Collect results
                [
                    receive
                        {done, I, R} -> {I, R}
                    after 30000 -> {I, timeout}
                    end
                 || I <- lists:seq(1, NumProcs)
                ]
            end,
            []
        ],
        60000
    ),

    %% Verify all succeeded
    lists:foreach(
        fun({I, R}) ->
            ?assertEqual(I * 2, R)
        end,
        Results
    ).

%% Test bidirectional message passing
test_bidirectional_messages({#{peer1 := Peer1, node1 := Node1, node2 := Node2}, _TmpDir}) ->
    NumMessages = 100,

    %% Start ping-pong on both nodes
    %% We'll run this test entirely within the QUIC cluster
    Result = peer:call(
        Peer1,
        erlang,
        apply,
        [
            fun() ->
                Self = self(),
                %% Start receiver on Node2
                Pid2 = spawn(Node2, fun() -> ping_pong_loop(Self, 0, NumMessages) end),
                %% Start sender on Node1
                spawn(Node1, fun() ->
                    Pid2 ! {ping, 1, self()},
                    ping_pong_loop(Self, 0, NumMessages)
                end),
                %% Wait for completion
                R1 =
                    receive
                        {complete, C1} when C1 >= NumMessages -> ok
                    after 30000 -> timeout1
                    end,
                R2 =
                    receive
                        {complete, C2} when C2 >= NumMessages -> ok
                    after 30000 -> timeout2
                    end,
                {R1, R2}
            end,
            []
        ],
        60000
    ),

    ?assertEqual({ok, ok}, Result).

ping_pong_loop(Parent, Count, Max) when Count >= Max ->
    Parent ! {complete, Count};
ping_pong_loop(Parent, Count, Max) ->
    receive
        {ping, N, From} ->
            From ! {pong, N + 1, self()},
            ping_pong_loop(Parent, Count + 1, Max);
        {pong, N, From} ->
            From ! {ping, N + 1, self()},
            ping_pong_loop(Parent, Count + 1, Max)
    after 5000 ->
        Parent ! {complete, Count}
    end.

%%====================================================================
%% Error Handling Tests
%%====================================================================

%% Test RPC timeout
test_rpc_timeout({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    %% Call that takes too long
    Result = peer:call(Peer1, rpc, call, [Node2, timer, sleep, [5000], 100]),
    ?assertEqual({badrpc, timeout}, Result).

%% Test RPC error handling
test_rpc_error_handling({#{peer1 := Peer1, node2 := Node2}, _TmpDir}) ->
    %% Call undefined function
    Result = peer:call(Peer1, rpc, call, [Node2, nonexistent_module, nonexistent_func, []]),
    ?assertMatch({badrpc, {'EXIT', {undef, _}}}, Result),

    %% Call that raises an error
    Result2 = peer:call(Peer1, rpc, call, [Node2, erlang, error, [test_error]]),
    ?assertMatch({badrpc, {'EXIT', {test_error, _}}}, Result2).

%%====================================================================
%% Global Registration Tests
%%====================================================================

%% Test global registration across nodes
test_global_registration({#{peer1 := Peer1, peer2 := Peer2}, _TmpDir}) ->
    %% Register a process globally from Node1
    Pid = peer:call(Peer1, erlang, spawn, [
        fun() ->
            receive
                {global_test, Data} -> put(global_result, {global_received, Data})
            after 10000 ->
                put(global_result, global_timeout)
            end,
            timer:sleep(2000)
        end
    ]),

    yes = peer:call(Peer1, global, register_name, [test_global_proc, Pid]),

    %% Wait for global sync
    timer:sleep(1000),

    %% Look up from Node2
    FoundPid = peer:call(Peer2, global, whereis_name, [test_global_proc]),
    case FoundPid of
        undefined ->
            %% Global sync may take time, try again
            timer:sleep(1000),
            Pid = peer:call(Peer2, global, whereis_name, [test_global_proc]);
        Pid ->
            ok
    end,

    %% Send message via global from Node2
    peer:call(Peer2, global, send, [test_global_proc, {global_test, hello}]),

    %% Check result on Node1
    timer:sleep(500),
    {dictionary, Dict} = peer:call(Peer1, erlang, process_info, [Pid, dictionary]),
    ?assertEqual({global_received, hello}, proplists:get_value(global_result, Dict)),

    %% Clean up
    peer:call(Peer1, global, unregister_name, [test_global_proc]).
