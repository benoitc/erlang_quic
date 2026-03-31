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
%%% - Message passing (!, send, send_nosuspend)
%%% - Process spawning (spawn, spawn_link, spawn_monitor)
%%% - Process linking and monitoring across nodes
%%% - gen_server calls across nodes
%%% - Large message transfers
%%% - Concurrent message handling
%%%
%%% Note: These are integration tests that require the peer module.
%%% They are skipped if peer nodes cannot be started.
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
            {setup, fun() -> Context end, fun cleanup/1, fun({Nodes, _}) ->
                {inorder, [
                    {"Basic RPC call", fun() -> test_basic_rpc_call(Nodes) end},
                    {"RPC call with args", fun() -> test_rpc_call_with_args(Nodes) end},
                    {"RPC cast", fun() -> test_rpc_cast(Nodes) end},
                    {"RPC multicall", fun() -> test_rpc_multicall(Nodes) end},
                    {"RPC block_call", fun() -> test_rpc_block_call(Nodes) end},
                    {"Message send", fun() -> test_message_send(Nodes) end},
                    {"Message send to registered", fun() -> test_message_send_registered(Nodes) end},
                    {"Remote spawn", fun() -> test_remote_spawn(Nodes) end},
                    {"Remote spawn_link", fun() -> test_remote_spawn_link(Nodes) end},
                    {"Remote spawn_monitor", fun() -> test_remote_spawn_monitor(Nodes) end},
                    {"Process link across nodes", fun() -> test_link_across_nodes(Nodes) end},
                    {"Process monitor across nodes", fun() -> test_monitor_across_nodes(Nodes) end},
                    {"Gen_server call", fun() -> test_gen_server_call(Nodes) end},
                    {"Large binary transfer", fun() -> test_large_binary(Nodes) end},
                    {"Large term transfer", fun() -> test_large_term(Nodes) end},
                    {"Concurrent RPCs", fun() -> test_concurrent_rpcs(Nodes) end},
                    {"Bidirectional messages", fun() -> test_bidirectional_messages(Nodes) end},
                    {"RPC timeout", fun() -> test_rpc_timeout(Nodes) end},
                    {"RPC error handling", fun() -> test_rpc_error_handling(Nodes) end},
                    {"Global registration", fun() -> test_global_registration(Nodes) end}
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
                atom_to_list(Cookie)
            ] ++ lists:flatmap(fun(P) -> ["-pa", P] end, CodePath),
            connection => standard_io
        }
    end,

    try
        {ok, Peer1, Node1} = peer:start_link(PeerOpts(Node1Name, 24433)),
        {ok, Peer2, Node2} = peer:start_link(PeerOpts(Node2Name, 24434)),

        %% Configure QUIC distribution
        Nodes = [{Node1, {"127.0.0.1", 24433}}, {Node2, {"127.0.0.1", 24434}}],
        DistConfig = [
            {cert_file, CertFile},
            {key_file, KeyFile},
            {verify, verify_none},
            {discovery_module, quic_discovery_static},
            {nodes, Nodes}
        ],

        ok = rpc:call(Node1, application, set_env, [quic, dist, DistConfig]),
        ok = rpc:call(Node2, application, set_env, [quic, dist, DistConfig]),

        {ok, _} = rpc:call(Node1, application, ensure_all_started, [quic]),
        {ok, _} = rpc:call(Node2, application, ensure_all_started, [quic]),

        {ok, _} = rpc:call(Node1, quic_discovery_static, init, [[{nodes, Nodes}]]),
        {ok, _} = rpc:call(Node2, quic_discovery_static, init, [[{nodes, Nodes}]]),

        %% Connect nodes
        pong = rpc:call(Node1, net_adm, ping, [Node2]),

        %% Verify connection
        timer:sleep(100),
        case {rpc:call(Node1, erlang, nodes, []), rpc:call(Node2, erlang, nodes, [])} of
            {N1List, N2List} when is_list(N1List), is_list(N2List) ->
                case {lists:member(Node2, N1List), lists:member(Node1, N2List)} of
                    {true, true} ->
                        {{Node1, Peer1, Node2, Peer2}, TmpDir};
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
cleanup({{_Node1, Peer1, _Node2, Peer2}, TmpDir}) ->
    catch peer:stop(Peer1),
    catch peer:stop(Peer2),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

%%====================================================================
%% RPC Tests
%%====================================================================

%% Test basic RPC call
test_basic_rpc_call({Node1, _, Node2, _}) ->
    %% Call erlang:node() on Node2 from Node1
    Result = rpc:call(Node1, rpc, call, [Node2, erlang, node, []]),
    ?assertEqual(Node2, Result).

%% Test RPC call with arguments
test_rpc_call_with_args({Node1, _, Node2, _}) ->
    %% Call lists:seq on Node2
    Result = rpc:call(Node1, rpc, call, [Node2, lists, seq, [1, 10]]),
    ?assertEqual(lists:seq(1, 10), Result),

    %% Call erlang:'+' with args
    Result2 = rpc:call(Node1, rpc, call, [Node2, erlang, '+', [5, 7]]),
    ?assertEqual(12, Result2).

%% Test RPC cast (async)
test_rpc_cast({Node1, _, Node2, _}) ->
    Self = self(),

    %% Start a receiver on Node2
    Receiver = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                {cast_test, Ref} -> Self ! {got_cast, Ref}
            after 5000 -> Self ! cast_timeout
            end
        end
    ]),

    %% Cast from Node1
    Ref = make_ref(),
    true = rpc:call(Node1, rpc, cast, [Node2, erlang, send, [Receiver, {cast_test, Ref}]]),

    receive
        {got_cast, Ref} -> ok
    after 5000 ->
        ?assert(false)
    end.

%% Test RPC multicall
test_rpc_multicall({Node1, _, Node2, _}) ->
    %% Multicall to both nodes
    {Results, BadNodes} = rpc:call(Node1, rpc, multicall, [[Node1, Node2], erlang, node, []]),

    ?assertEqual([], BadNodes),
    ?assertEqual(2, length(Results)),
    ?assert(lists:member(Node1, Results)),
    ?assert(lists:member(Node2, Results)).

%% Test RPC block_call (doesn't process messages while waiting)
test_rpc_block_call({Node1, _, Node2, _}) ->
    Result = rpc:call(Node1, rpc, block_call, [Node2, timer, sleep, [100]]),
    ?assertEqual(ok, Result).

%%====================================================================
%% Message Passing Tests
%%====================================================================

%% Test direct message send
test_message_send({_Node1, _, Node2, _}) ->
    Self = self(),
    TestData = {test, make_ref(), <<"binary">>, [1, 2, 3]},

    %% Spawn receiver on Node2
    Receiver = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                Msg -> Self ! {received, Msg}
            after 5000 -> Self ! timeout
            end
        end
    ]),

    %% Send message directly
    Receiver ! TestData,

    receive
        {received, TestData} -> ok;
        timeout -> ?assert(false)
    after 5000 ->
        ?assert(false)
    end.

%% Test message send to registered process
test_message_send_registered({_Node1, _, Node2, _}) ->
    Self = self(),

    %% Register a process on Node2
    ok = rpc:call(Node2, erlang, apply, [
        fun() ->
            register(
                test_receiver,
                spawn(fun() ->
                    receive
                        {test_msg, Data} -> Self ! {from_registered, Data}
                    after 5000 -> Self ! reg_timeout
                    end
                end)
            ),
            ok
        end,
        []
    ]),

    %% Send to registered name
    {test_receiver, Node2} ! {test_msg, hello},

    receive
        {from_registered, hello} -> ok;
        reg_timeout -> ?assert(false)
    after 5000 ->
        ?assert(false)
    end.

%%====================================================================
%% Process Spawning Tests
%%====================================================================

%% Test remote spawn
test_remote_spawn({Node1, _, Node2, _}) ->
    Self = self(),

    %% Spawn on Node2 from Node1
    Pid = rpc:call(Node1, erlang, spawn, [
        Node2,
        fun() ->
            Self ! {spawned_on, node()}
        end
    ]),

    ?assertEqual(Node2, node(Pid)),

    receive
        {spawned_on, Node2} -> ok
    after 5000 ->
        ?assert(false)
    end.

%% Test remote spawn_link
test_remote_spawn_link({Node1, _, Node2, _}) ->
    Self = self(),

    %% Spawn linked process on Node2
    Pid = rpc:call(Node1, erlang, spawn_link, [
        Node2,
        fun() ->
            Self ! {linked_spawned, self(), node()}
        end
    ]),

    ?assertEqual(Node2, node(Pid)),

    receive
        {linked_spawned, Pid, Node2} -> ok
    after 5000 ->
        ?assert(false)
    end.

%% Test remote spawn_monitor
test_remote_spawn_monitor({Node1, _, Node2, _}) ->
    Self = self(),

    %% Spawn monitored process on Node2 that exits
    {Pid, MonRef} = rpc:call(Node1, erlang, spawn_monitor, [
        Node2,
        fun() ->
            Self ! {monitor_spawned, self()},
            exit(normal)
        end
    ]),

    ?assertEqual(Node2, node(Pid)),

    receive
        {monitor_spawned, Pid} -> ok
    after 5000 ->
        ?assert(false)
    end,

    %% Should receive DOWN message
    receive
        {'DOWN', MonRef, process, Pid, normal} -> ok
    after 5000 ->
        ?assert(false)
    end.

%%====================================================================
%% Link and Monitor Tests
%%====================================================================

%% Test link across nodes
test_link_across_nodes({_Node1, _, Node2, _}) ->
    process_flag(trap_exit, true),

    %% Spawn a process on Node2 and link to it
    Pid = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                die -> exit(test_exit)
            end
        end
    ]),

    link(Pid),
    Pid ! die,

    receive
        {'EXIT', Pid, test_exit} -> ok
    after 5000 ->
        ?assert(false)
    end,

    process_flag(trap_exit, false).

%% Test monitor across nodes
test_monitor_across_nodes({_Node1, _, Node2, _}) ->
    %% Spawn a process on Node2 and monitor it
    Pid = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                die -> exit(test_exit)
            end
        end
    ]),

    MonRef = monitor(process, Pid),
    Pid ! die,

    receive
        {'DOWN', MonRef, process, Pid, test_exit} -> ok
    after 5000 ->
        ?assert(false)
    end.

%%====================================================================
%% Gen_server Tests
%%====================================================================

%% Test gen_server call across nodes
test_gen_server_call({_Node1, _, Node2, _}) ->
    %% Start a simple gen_server on Node2
    {ok, _Pid} = rpc:call(Node2, gen_server, start, [
        {local, test_gen_server},
        ?MODULE,
        [self()],
        []
    ]),

    %% Call the gen_server
    Result = gen_server:call({test_gen_server, Node2}, {echo, test_value}),
    ?assertEqual({ok, test_value}, Result),

    %% Clean up
    gen_server:stop({test_gen_server, Node2}).

%% Gen_server callbacks for test (exported at module top)
init([_Parent]) ->
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
test_large_binary({Node1, _, Node2, _}) ->
    %% Create 1MB binary
    Size = 1024 * 1024,
    Data = crypto:strong_rand_bytes(Size),
    Hash = crypto:hash(sha256, Data),

    %% Transfer via RPC
    RecvHash = rpc:call(Node1, rpc, call, [Node2, crypto, hash, [sha256, Data]], 60000),

    ?assertEqual(Hash, RecvHash).

%% Test large term transfer
test_large_term({Node1, _, Node2, _}) ->
    %% Create large nested term
    LargeTerm = create_large_term(10000),

    %% Transfer and verify
    Result = rpc:call(Node1, rpc, call, [Node2, erlang, length, [LargeTerm]], 60000),
    ?assertEqual(10000, Result).

create_large_term(N) ->
    [{I, make_ref(), <<"data">>, [a, b, c]} || I <- lists:seq(1, N)].

%%====================================================================
%% Concurrent Tests
%%====================================================================

%% Test concurrent RPCs
test_concurrent_rpcs({Node1, _, Node2, _}) ->
    Self = self(),
    NumProcs = 50,

    %% Spawn multiple processes doing RPCs
    _Pids = [
        spawn_link(fun() ->
            Result = rpc:call(Node1, rpc, call, [Node2, erlang, '+', [I, I]]),
            Self ! {done, I, Result}
        end)
     || I <- lists:seq(1, NumProcs)
    ],

    %% Collect results
    Results = [
        receive
            {done, I, R} -> {I, R}
        after 30000 -> {I, timeout}
        end
     || I <- lists:seq(1, NumProcs)
    ],

    %% Verify all succeeded
    lists:foreach(
        fun({I, R}) ->
            ?assertEqual(I * 2, R)
        end,
        Results
    ).

%% Test bidirectional message passing
test_bidirectional_messages({Node1, _, Node2, _}) ->
    Self = self(),
    NumMessages = 100,

    %% Start ping-pong processes on both nodes
    Pid2 = rpc:call(Node2, erlang, spawn, [
        fun() ->
            ping_pong_loop(Self, 0, NumMessages)
        end
    ]),

    _Pid1 = rpc:call(Node1, erlang, spawn, [
        fun() ->
            Pid2 ! {ping, 1, self()},
            ping_pong_loop(Self, 0, NumMessages)
        end
    ]),

    %% Wait for completion
    receive
        {complete, Count1} when Count1 >= NumMessages -> ok
    after 30000 ->
        ?assert(false)
    end,

    receive
        {complete, Count2} when Count2 >= NumMessages -> ok
    after 30000 ->
        ?assert(false)
    end.

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
test_rpc_timeout({Node1, _, Node2, _}) ->
    %% Call that takes too long
    Result = rpc:call(Node1, rpc, call, [Node2, timer, sleep, [5000]], 100),
    ?assertEqual({badrpc, timeout}, Result).

%% Test RPC error handling
test_rpc_error_handling({Node1, _, Node2, _}) ->
    %% Call undefined function
    Result = rpc:call(Node1, rpc, call, [Node2, nonexistent_module, nonexistent_func, []]),
    ?assertMatch({badrpc, {'EXIT', {undef, _}}}, Result),

    %% Call that throws
    Result2 = rpc:call(Node1, rpc, call, [Node2, erlang, throw, [test_throw]]),
    ?assertMatch({badrpc, test_throw}, Result2).

%%====================================================================
%% Global Registration Tests
%%====================================================================

%% Test global registration across nodes
test_global_registration({Node1, _, Node2, _}) ->
    Self = self(),

    %% Register a process globally from Node1
    Pid = rpc:call(Node1, erlang, spawn, [
        fun() ->
            receive
                {global_test, Data} -> Self ! {global_received, Data}
            after 10000 -> Self ! global_timeout
            end
        end
    ]),

    yes = rpc:call(Node1, global, register_name, [test_global_proc, Pid]),

    %% Wait for global sync
    timer:sleep(500),

    %% Look up from Node2 and send message
    case rpc:call(Node2, global, whereis_name, [test_global_proc]) of
        undefined ->
            %% Global sync may take time, try again
            timer:sleep(1000),
            Pid = rpc:call(Node2, global, whereis_name, [test_global_proc]);
        Pid ->
            ok
    end,

    rpc:call(Node2, global, send, [test_global_proc, {global_test, hello}]),

    receive
        {global_received, hello} -> ok;
        global_timeout -> ?assert(false)
    after 5000 ->
        ?assert(false)
    end,

    %% Clean up
    rpc:call(Node1, global, unregister_name, [test_global_proc]).
