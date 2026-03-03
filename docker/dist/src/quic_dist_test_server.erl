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
    echo_data/1
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
    Results1 = test_basic_rpc(),
    Results2 = test_large_messages(),

    %% Log individual results
    log_test_results(basic, Results1),
    log_test_results(large_msg, Results2),

    [{basic, Results1}, {large_msg, Results2}].

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
    case rpc:call(Node, ?MODULE, echo_data, [Data], 60000) of
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

log_event(Event, Data) ->
    Timestamp = calendar:system_time_to_rfc3339(erlang:system_time(millisecond), [{unit, millisecond}]),
    io:format("[DIST_TEST] ~s ~p ~p~n", [Timestamp, Event, Data]).
