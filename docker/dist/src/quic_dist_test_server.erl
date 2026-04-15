%%% -*- erlang -*-
%%%
%%% QUIC Distribution Test Server
%%%
%%% This gen_server manages the test execution for QUIC distribution testing.
%%% It monitors node connections, runs various test phases, and logs results
%%% in a format that can be verified by external scripts.
%%%

-module(quic_dist_test_server).

-behaviour(gen_server).

%% API
-export([
    start_link/0,
    list_connections/0,
    broadcast_test/0,
    get_stats/0,
    echo/1,
    echo_data/1,
    start_stream_acceptor/1
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    messages_sent = 0 :: non_neg_integer(),
    messages_received = 0 :: non_neg_integer(),
    connected_nodes = [] :: [node()],
    test_results = [] :: [{atom(), [{node(), term()}]}],
    test_phase = init :: init | connecting | testing | done,
    expected_nodes :: non_neg_integer() | undefined
}).

-define(SERVER, ?MODULE).
-define(CONNECT_RETRY_INTERVAL, 1000).
-define(TEST_START_DELAY, 5000).
-define(LARGE_MSG_SIZE, 1024 * 1024).  % 1MB

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

list_connections() ->
    gen_server:call(?SERVER, list_connections).

broadcast_test() ->
    gen_server:call(?SERVER, broadcast_test, 30000).

get_stats() ->
    gen_server:call(?SERVER, get_stats).

%% Echo functions called via RPC
echo(Ref) ->
    {ok, Ref}.

echo_data(Data) ->
    Data.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    net_kernel:monitor_nodes(true),
    ExpectedNodes = get_expected_node_count(),
    log_event(init, #{node => node(), expected_nodes => ExpectedNodes}),

    %% Schedule initial connection attempt
    erlang:send_after(?CONNECT_RETRY_INTERVAL, self(), try_connect),

    {ok, #state{expected_nodes = ExpectedNodes, test_phase = init}}.

handle_call(list_connections, _From, State) ->
    {reply, {ok, State#state.connected_nodes}, State};

handle_call(broadcast_test, _From, State) ->
    Results = run_all_tests(),
    {reply, {ok, Results}, State#state{test_results = Results}};

handle_call(get_stats, _From, State) ->
    Stats = #{
        messages_sent => State#state.messages_sent,
        messages_received => State#state.messages_received,
        connected_nodes => State#state.connected_nodes,
        test_phase => State#state.test_phase,
        test_results => State#state.test_results
    },
    {reply, {ok, Stats}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({nodeup, Node}, State) ->
    log_event(nodeup, Node),
    NewNodes = [Node | lists:delete(Node, State#state.connected_nodes)],
    NewState = State#state{connected_nodes = NewNodes},

    %% Check if we have all expected nodes
    ExpectedPeers = State#state.expected_nodes - 1,
    case length(NewNodes) >= ExpectedPeers of
        true when State#state.test_phase =:= connecting ->
            log_event(mesh_complete, #{nodes => length(NewNodes) + 1}),
            %% Schedule tests
            erlang:send_after(?TEST_START_DELAY, self(), run_tests),
            {noreply, NewState#state{test_phase = testing}};
        _ ->
            {noreply, NewState}
    end;

handle_info({nodedown, Node}, State) ->
    log_event(nodedown, Node),
    NewNodes = lists:delete(Node, State#state.connected_nodes),
    {noreply, State#state{connected_nodes = NewNodes}};

handle_info(try_connect, State) ->
    connect_to_cluster(),
    NewState = State#state{test_phase = connecting},

    %% Check if we're already connected to all peers
    CurrentPeers = length(nodes()),
    ExpectedPeers = State#state.expected_nodes - 1,

    case CurrentPeers >= ExpectedPeers of
        true when ExpectedPeers > 0 ->
            log_event(mesh_complete, #{nodes => CurrentPeers + 1}),
            erlang:send_after(?TEST_START_DELAY, self(), run_tests),
            {noreply, NewState#state{
                connected_nodes = nodes(),
                test_phase = testing
            }};
        true when ExpectedPeers =:= 0 ->
            %% Single node test
            log_event(single_node_mode, #{}),
            erlang:send_after(?TEST_START_DELAY, self(), run_tests),
            {noreply, NewState#state{test_phase = testing}};
        false ->
            %% Keep trying
            erlang:send_after(?CONNECT_RETRY_INTERVAL, self(), try_connect),
            {noreply, NewState#state{connected_nodes = nodes()}}
    end;

handle_info(run_tests, State) ->
    log_event(test_start, #{connected => nodes()}),
    Results = run_all_tests(),

    %% Log summary
    {SuccessCount, FailCount} = count_results(Results),
    log_event(test_complete, #{success => SuccessCount, failed => FailCount}),

    {noreply, State#state{test_results = Results, test_phase = done}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal functions
%%====================================================================

get_expected_node_count() ->
    case os:getenv("EXPECTED_NODES") of
        false -> 2;  % Default to 2 nodes
        Val ->
            try list_to_integer(Val) of
                N when N > 0 -> N;
                _ -> 2
            catch
                _:_ -> 2
            end
    end.

connect_to_cluster() ->
    SeedNode = get_seed_node(),
    ExpectedCount = get_expected_node_count(),

    %% Only try to connect to seed node for non-seed nodes
    %% This avoids simultaneous connection attempts
    case SeedNode of
        undefined ->
            %% This is the seed node, wait for others to connect
            log_event(seed_node_waiting, #{expected => ExpectedCount}),
            ok;
        Seed when Seed =/= node() ->
            %% Only connect to seed, let the mesh form naturally
            ConnectedNodes = nodes(),
            case lists:member(Seed, ConnectedNodes) of
                true ->
                    log_event(already_connected, Seed),
                    ok;
                false ->
                    log_event(connecting, Seed),
                    case net_kernel:connect_node(Seed) of
                        true -> log_event(connected, Seed);
                        false -> log_event(connect_failed, Seed);
                        ignored -> log_event(connect_ignored, Seed)
                    end
            end;
        _ -> ok
    end.

get_seed_node() ->
    case os:getenv("SEED_NODE") of
        false -> undefined;
        "" -> undefined;
        NodeStr -> list_to_atom(NodeStr)
    end.

get_cluster_nodes() ->
    case os:getenv("CLUSTER_NODES") of
        false -> [];
        "" -> [];
        NodesStr ->
            NodeStrs = string:tokens(NodesStr, ","),
            [list_to_atom(string:trim(N)) || N <- NodeStrs]
    end.

run_all_tests() ->
    %% Log each test's result as soon as it returns. Logging at the end
    %% caused later tests (and the verify script) to miss earlier results
    %% whenever a middle test stalled.
    Results1 = test_basic_rpc(),
    log_test_results(basic, Results1),

    Results3 = test_throughput_benchmark(),

    Results2 = test_large_messages(),
    log_test_results(large_msg, Results2),

    Results4 = test_user_streams(),
    log_test_results(user_stream, Results4),

    [{basic, Results1}, {throughput, Results3}, {large_msg, Results2}, {user_stream, Results4}].

%% Test 3: Throughput benchmark
test_throughput_benchmark() ->
    Nodes = nodes(),
    case Nodes of
        [] -> [];
        [TargetNode | _] ->
            log_event(throughput_start, #{target => TargetNode}),
            Results = run_throughput_bench(TargetNode),
            log_event(throughput_complete, Results),
            [{TargetNode, {ok, Results}}]
    end.

run_throughput_bench(TargetNode) ->
    %% Spawn echo server on target
    ServerPid = spawn(TargetNode, fun() -> bench_echo_loop() end),

    Sizes = [64, 256, 1024, 4096, 16384, 65536],
    Iterations = 2000,
    PerRtTimeoutMs = 5000,

    Results = lists:map(fun(Size) ->
        Data = crypto:strong_rand_bytes(Size),

        %% Warmup (10 RTs, no measurement)
        lists:foreach(fun(_) ->
            Ref = make_ref(),
            ServerPid ! {echo, self(), Ref, Data},
            receive {echo_reply, Ref, _} -> ok after PerRtTimeoutMs -> ok end
        end, lists:seq(1, 10)),

        %% Benchmark — record per-RT latency, count timeouts
        Start = erlang:monotonic_time(microsecond),
        Latencies = lists:map(fun(_) ->
            Ref = make_ref(),
            T0 = erlang:monotonic_time(microsecond),
            ServerPid ! {echo, self(), Ref, Data},
            receive
                {echo_reply, Ref, _} ->
                    erlang:monotonic_time(microsecond) - T0
            after PerRtTimeoutMs ->
                timeout
            end
        end, lists:seq(1, Iterations)),
        Elapsed = erlang:monotonic_time(microsecond) - Start,

        {Stats, Timeouts} = summarize_latencies(Latencies),
        Throughput = Iterations / (Elapsed / 1000000),
        Bandwidth = Throughput * Size / 1048576,

        log_event(throughput_result, #{
            size => Size,
            iterations => Iterations,
            timeouts => Timeouts,
            elapsed_ms => round(Elapsed / 1000),
            bandwidth_mbps => round(Bandwidth * 100) / 100,
            min_us => maps:get(min, Stats, none),
            p50_us => maps:get(p50, Stats, none),
            p99_us => maps:get(p99, Stats, none),
            max_us => maps:get(max, Stats, none)
        }),

        {Size, Throughput, Bandwidth, Stats}
    end, Sizes),

    ServerPid ! stop,
    Results.

summarize_latencies(Latencies) ->
    {OK, Timeouts} = lists:partition(fun(timeout) -> false; (_) -> true end, Latencies),
    case OK of
        [] -> {#{}, length(Timeouts)};
        _ ->
            Sorted = lists:sort(OK),
            N = length(Sorted),
            Stats = #{
                min => hd(Sorted),
                p50 => lists:nth(max(1, N div 2), Sorted),
                p99 => lists:nth(max(1, (N * 99) div 100), Sorted),
                max => lists:last(Sorted)
            },
            {Stats, length(Timeouts)}
    end.

bench_echo_loop() ->
    receive
        {echo, From, Ref, Data} ->
            From ! {echo_reply, Ref, Data},
            bench_echo_loop();
        stop ->
            ok
    end.

%% Test 1: Basic RPC to all connected nodes
test_basic_rpc() ->
    Nodes = nodes(),
    [{Node, rpc_test(Node)} || Node <- Nodes].

rpc_test(Node) ->
    Ref = make_ref(),
    Start = erlang:monotonic_time(millisecond),
    case rpc:call(Node, ?MODULE, echo, [Ref], 5000) of
        {ok, Ref} ->
            Latency = erlang:monotonic_time(millisecond) - Start,
            {ok, Latency};
        {badrpc, Reason} ->
            {error, Reason};
        Other ->
            {error, {unexpected, Other}}
    end.

%% Test 2: Large message transfer (1MB)
test_large_messages() ->
    Nodes = nodes(),
    LargeData = crypto:strong_rand_bytes(?LARGE_MSG_SIZE),
    [{Node, large_msg_test(Node, LargeData)} || Node <- Nodes].

large_msg_test(Node, Data) ->
    Start = erlang:monotonic_time(millisecond),
    case rpc:call(Node, ?MODULE, echo_data, [Data], 120000) of
        Data ->
            Latency = erlang:monotonic_time(millisecond) - Start,
            {ok, Latency};
        {badrpc, Reason} ->
            {error, Reason};
        Other when is_binary(Other) ->
            {error, data_mismatch};
        Error ->
            {error, Error}
    end.

log_test_results(TestName, Results) ->
    lists:foreach(fun({Node, Result}) ->
        case Result of
            {ok, Latency} ->
                log_event(TestName, #{node => Node, status => ok, latency_ms => Latency});
            {error, Reason} ->
                log_event(TestName, #{node => Node, status => error, reason => Reason})
        end
    end, Results).

count_results(AllResults) ->
    lists:foldl(fun({_TestName, Results}, {S, F}) ->
        lists:foldl(fun({_Node, Result}, {S2, F2}) ->
            case Result of
                {ok, _} -> {S2 + 1, F2};
                {error, _} -> {S2, F2 + 1}
            end
        end, {S, F}, Results)
    end, {0, 0}, AllResults).

%% Test 4: User streams over QUIC distribution
test_user_streams() ->
    Nodes = nodes(),
    [{Node, user_stream_test(Node)} || Node <- Nodes].

user_stream_test(Node) ->
    %% Start acceptor on remote node (pass our node name)
    case rpc:call(Node, ?MODULE, start_stream_acceptor, [node()], 5000) of
        {ok, _AcceptorPid} ->
            %% Wait for acceptor to be ready
            timer:sleep(100),
            run_user_stream_test(Node);
        {badrpc, Reason} ->
            {error, {acceptor_start_failed, Reason}};
        Error ->
            {error, {acceptor_start_failed, Error}}
    end.

run_user_stream_test(Node) ->
    Start = erlang:monotonic_time(millisecond),
    case quic_dist:open_stream(Node) of
        {ok, Stream} ->
            TestData = <<"user_stream_test_", (crypto:strong_rand_bytes(32))/binary>>,
            case quic_dist:send(Stream, TestData, true) of
                ok ->
                    %% Wait for echo response
                    receive
                        {quic_dist_stream, Stream, {data, Response, true}} ->
                            quic_dist:close_stream(Stream),
                            case Response of
                                TestData ->
                                    Latency = erlang:monotonic_time(millisecond) - Start,
                                    {ok, Latency};
                                _ ->
                                    {error, data_mismatch}
                            end;
                        {quic_dist_stream, Stream, {reset, Code}} ->
                            {error, {stream_reset, Code}}
                    after 10000 ->
                        quic_dist:close_stream(Stream),
                        {error, timeout}
                    end;
                {error, Reason} ->
                    quic_dist:close_stream(Stream),
                    {error, {send_failed, Reason}}
            end;
        {error, Reason} ->
            {error, {open_failed, Reason}}
    end.

%% Start a stream acceptor on this node (called via RPC)
start_stream_acceptor(CallerNode) ->
    Pid = spawn(fun() -> stream_acceptor_loop(CallerNode) end),
    {ok, Pid}.

stream_acceptor_loop(CallerNode) ->
    ok = quic_dist:accept_streams(CallerNode),
    stream_acceptor_receive().

stream_acceptor_receive() ->
    receive
        {quic_dist_stream, Stream, {data, Data, true}} ->
            %% Echo data back
            quic_dist:send(Stream, Data, true),
            stream_acceptor_receive();
        {quic_dist_stream, Stream, {data, Data, false}} ->
            %% Accumulate partial data (simplified: just echo immediately)
            quic_dist:send(Stream, Data, false),
            stream_acceptor_receive();
        {quic_dist_stream, _Stream, closed} ->
            stream_acceptor_receive();
        {quic_dist_stream, _Stream, {reset, _Code}} ->
            stream_acceptor_receive();
        stop ->
            ok
    after 60000 ->
        %% Timeout after 1 minute of inactivity
        ok
    end.

log_event(Event, Data) ->
    Timestamp = calendar:system_time_to_rfc3339(erlang:system_time(millisecond), [{unit, millisecond}]),
    io:format("[DIST_TEST] ~s ~p ~p~n", [Timestamp, Event, Data]).
