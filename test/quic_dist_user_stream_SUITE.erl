%%% -*- erlang -*-
%%%
%%% QUIC Distribution User Stream Integration Tests
%%% Tests user stream functionality over QUIC distribution
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_user_stream_SUITE).

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
    open_stream_test/1,
    send_receive_test/1,
    bidirectional_test/1,
    large_data_test/1,
    multiple_streams_test/1,
    close_stream_test/1,
    owner_death_test/1,
    accept_streams_test/1,
    fin_flag_test/1
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
            open_stream_test,
            send_receive_test,
            bidirectional_test,
            large_data_test,
            multiple_streams_test,
            close_stream_test,
            owner_death_test,
            accept_streams_test,
            fin_flag_test
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
                    %% Connect nodes
                    pong = rpc:call(Node1, net_adm, ping, [Node2]),
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

%% Test opening a user stream
open_stream_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Open stream from Node1 to Node2
    Result = rpc:call(Node1, quic_dist, open_stream, [Node2]),
    ?assertMatch({ok, {quic_dist_stream, Node2, _}}, Result),

    {ok, StreamRef} = Result,
    {quic_dist_stream, _, StreamId} = StreamRef,
    % Above threshold
    ?assert(StreamId >= 20),

    %% Clean up
    ok = rpc:call(Node1, quic_dist, close_stream, [StreamRef]),
    ok.

%% Test sending and receiving data
send_receive_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),
    Self = self(),

    %% Set up receiver on Node2
    ok = rpc:call(Node2, quic_dist, accept_streams, [Node1]),

    %% Spawn receiver process on Node2
    ReceiverPid = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                {quic_dist_stream, Node1, {incoming, StreamId}} ->
                    {ok, StreamRef} = quic_dist:accept_incoming_stream(Node1, StreamId),
                    receive
                        {quic_dist_stream, StreamRef, {data, Data, _Fin}} ->
                            Self ! {received, Data}
                    after 5000 ->
                        Self ! timeout
                    end
            after 5000 ->
                Self ! no_incoming
            end
        end
    ]),

    %% Re-register receiver as acceptor
    ok = rpc:call(Node2, quic_dist, accept_streams, [Node1]),
    %% Need to update acceptor to our spawned process
    {ok, Ctrl} = rpc:call(Node2, quic_dist, get_controller, [Node1]),
    ok = rpc:call(Node2, quic_dist_controller, accept_user_streams, [Ctrl, ReceiverPid]),

    %% Open stream from Node1 and send data
    {ok, Stream} = rpc:call(Node1, quic_dist, open_stream, [Node2]),
    TestData = <<"Hello from user stream!">>,
    ok = rpc:call(Node1, quic_dist, send, [Stream, TestData]),

    %% Wait for data
    receive
        {received, TestData} -> ok;
        {received, Other} -> ct:fail({wrong_data, Other});
        timeout -> ct:fail(receive_timeout);
        no_incoming -> ct:fail(no_incoming_stream)
    after 10000 ->
        ct:fail(test_timeout)
    end,

    %% Clean up
    ok = rpc:call(Node1, quic_dist, close_stream, [Stream]),
    ok = rpc:call(Node2, quic_dist, stop_accepting, [Node1]),
    ok.

%% Test bidirectional communication
bidirectional_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),
    Self = self(),

    %% Set up acceptor on Node2
    {ok, Ctrl2} = rpc:call(Node2, quic_dist, get_controller, [Node1]),

    ReceiverPid = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                {quic_dist_stream, Node1, {incoming, StreamId}} ->
                    {ok, StreamRef} = quic_dist:accept_incoming_stream(Node1, StreamId),
                    %% Receive data
                    receive
                        {quic_dist_stream, StreamRef, {data, Data, _}} ->
                            %% Echo back with modification
                            Response = <<"Echo: ", Data/binary>>,
                            ok = quic_dist:send(StreamRef, Response),
                            Self ! echoed
                    after 5000 ->
                        Self ! timeout
                    end
            after 5000 ->
                Self ! no_incoming
            end
        end
    ]),

    ok = rpc:call(Node2, quic_dist_controller, accept_user_streams, [Ctrl2, ReceiverPid]),

    %% Open stream from Node1 and send data
    {ok, Stream} = rpc:call(Node1, quic_dist, open_stream, [Node2]),
    ok = rpc:call(Node1, quic_dist, send, [Stream, <<"Test">>]),

    %% Wait for echo confirmation
    receive
        echoed -> ok;
        timeout -> ct:fail(echo_timeout);
        no_incoming -> ct:fail(no_incoming)
    after 10000 ->
        ct:fail(bidirectional_timeout)
    end,

    %% Clean up
    ok = rpc:call(Node1, quic_dist, close_stream, [Stream]),
    ok.

%% Test large data transfer
large_data_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),
    Self = self(),

    %% Create 1MB of data
    LargeData = crypto:strong_rand_bytes(1024 * 1024),
    Hash = crypto:hash(sha256, LargeData),

    %% Set up receiver
    {ok, Ctrl2} = rpc:call(Node2, quic_dist, get_controller, [Node1]),

    ReceiverPid = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                {quic_dist_stream, Node1, {incoming, StreamId}} ->
                    {ok, StreamRef} = quic_dist:accept_incoming_stream(Node1, StreamId),
                    collect_data(StreamRef, [], Self)
            after 10000 ->
                Self ! no_incoming
            end
        end
    ]),

    ok = rpc:call(Node2, quic_dist_controller, accept_user_streams, [Ctrl2, ReceiverPid]),

    %% Send large data
    {ok, Stream} = rpc:call(Node1, quic_dist, open_stream, [Node2]),
    ok = rpc:call(Node1, quic_dist, send, [Stream, LargeData, true]),

    %% Wait for hash verification
    receive
        {hash_match, true} -> ok;
        {hash_match, false} -> ct:fail(hash_mismatch);
        {collected, RecvHash} -> ?assertEqual(Hash, RecvHash);
        no_incoming -> ct:fail(no_incoming)
    after 60000 ->
        ct:fail(large_data_timeout)
    end,

    ok.

%% Test multiple concurrent streams
multiple_streams_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Open 10 streams
    NumStreams = 10,
    Streams = lists:map(
        fun(_) ->
            {ok, Stream} = rpc:call(Node1, quic_dist, open_stream, [Node2]),
            Stream
        end,
        lists:seq(1, NumStreams)
    ),

    ?assertEqual(NumStreams, length(Streams)),

    %% Verify all stream IDs are unique
    StreamIds = [Id || {quic_dist_stream, _, Id} <- Streams],
    ?assertEqual(NumStreams, length(lists:usort(StreamIds))),

    %% Clean up
    lists:foreach(
        fun(Stream) ->
            ok = rpc:call(Node1, quic_dist, close_stream, [Stream])
        end,
        Streams
    ),
    ok.

%% Test stream close
close_stream_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Open and close stream
    {ok, Stream} = rpc:call(Node1, quic_dist, open_stream, [Node2]),
    ok = rpc:call(Node1, quic_dist, close_stream, [Stream]),

    %% Sending on closed stream should fail
    Result = rpc:call(Node1, quic_dist, send, [Stream, <<"test">>]),
    ?assertMatch({error, _}, Result),

    ok.

%% Test owner death cleanup
owner_death_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),

    %% Spawn a process that opens a stream and dies
    OwnerPid = rpc:call(Node1, erlang, spawn, [
        fun() ->
            {ok, _Stream} = quic_dist:open_stream(Node2),
            %% Exit immediately, stream should be cleaned up
            ok
        end
    ]),

    %% Wait for process to die
    timer:sleep(100),
    ?assertEqual(false, rpc:call(Node1, erlang, is_process_alive, [OwnerPid])),

    %% Stream should be cleaned up (no way to verify directly, but no crash)
    ok.

%% Test accept_streams functionality
accept_streams_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),
    Self = self(),

    %% Set up acceptor on Node2
    {ok, Ctrl2} = rpc:call(Node2, quic_dist, get_controller, [Node1]),

    AcceptorPid = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                {quic_dist_stream, Node1, {incoming, StreamId}} ->
                    Self ! {got_incoming, StreamId}
            after 5000 ->
                Self ! timeout
            end
        end
    ]),

    ok = rpc:call(Node2, quic_dist_controller, accept_user_streams, [Ctrl2, AcceptorPid]),

    %% Open stream from Node1
    {ok, Stream} = rpc:call(Node1, quic_dist, open_stream, [Node2]),

    %% Send some data to trigger the incoming notification
    ok = rpc:call(Node1, quic_dist, send, [Stream, <<"trigger">>]),

    %% Verify acceptor got notification
    receive
        {got_incoming, StreamId} ->
            {quic_dist_stream, _, ExpectedId} = Stream,
            ?assertEqual(ExpectedId, StreamId);
        timeout ->
            ct:fail(no_incoming_notification)
    after 5000 ->
        ct:fail(accept_streams_timeout)
    end,

    %% Clean up
    ok = rpc:call(Node1, quic_dist, close_stream, [Stream]),
    ok = rpc:call(Node2, quic_dist, stop_accepting, [Node1]),
    ok.

%% Test FIN flag semantics
fin_flag_test(Config) ->
    Node1 = proplists:get_value(node1, Config),
    Node2 = proplists:get_value(node2, Config),
    Self = self(),

    %% Set up receiver
    {ok, Ctrl2} = rpc:call(Node2, quic_dist, get_controller, [Node1]),

    ReceiverPid = rpc:call(Node2, erlang, spawn, [
        fun() ->
            receive
                {quic_dist_stream, Node1, {incoming, StreamId}} ->
                    {ok, StreamRef} = quic_dist:accept_incoming_stream(Node1, StreamId),
                    fin_receiver_loop(StreamRef, Self)
            after 5000 ->
                Self ! no_incoming
            end
        end
    ]),

    ok = rpc:call(Node2, quic_dist_controller, accept_user_streams, [Ctrl2, ReceiverPid]),

    %% Open stream and send data without FIN
    {ok, Stream} = rpc:call(Node1, quic_dist, open_stream, [Node2]),
    ok = rpc:call(Node1, quic_dist, send, [Stream, <<"part1">>]),
    ok = rpc:call(Node1, quic_dist, send, [Stream, <<"part2">>]),
    %% Send final data with FIN
    ok = rpc:call(Node1, quic_dist, send, [Stream, <<"final">>, true]),

    %% Wait for receiver to get all data and FIN
    receive
        {fin_received, Chunks} ->
            %% Verify we got data and final FIN flag was true
            ?assert(length(Chunks) >= 1),
            {_, LastFin} = lists:last(Chunks),
            ?assertEqual(true, LastFin);
        no_incoming ->
            ct:fail(no_incoming)
    after 10000 ->
        ct:fail(fin_flag_timeout)
    end,

    ok.

%%====================================================================
%% Helper Functions
%%====================================================================

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
    _PrivDir = proplists:get_value(priv_dir, Config),

    Node1Name = list_to_atom(
        "quic_us_node1_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    Node2Name = list_to_atom(
        "quic_us_node2_" ++ integer_to_list(erlang:unique_integer([positive]))
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

    %% Start peer nodes with unique ports
    try
        {ok, Peer1, Node1} = peer:start_link(PeerOpts(Node1Name, 15433)),
        {ok, Peer2, Node2} = peer:start_link(PeerOpts(Node2Name, 15434)),

        %% Configure QUIC distribution on nodes
        Nodes = [
            {Node1, {"127.0.0.1", 15433}},
            {Node2, {"127.0.0.1", 15434}}
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

%% Helper to collect data chunks until FIN
collect_data(StreamRef, Acc, Parent) ->
    receive
        {quic_dist_stream, StreamRef, {data, Data, true}} ->
            %% Final chunk
            AllData = iolist_to_binary(lists:reverse([Data | Acc])),
            Hash = crypto:hash(sha256, AllData),
            Parent ! {collected, Hash};
        {quic_dist_stream, StreamRef, {data, Data, false}} ->
            collect_data(StreamRef, [Data | Acc], Parent);
        {quic_dist_stream, StreamRef, closed} ->
            AllData = iolist_to_binary(lists:reverse(Acc)),
            Hash = crypto:hash(sha256, AllData),
            Parent ! {collected, Hash}
    after 30000 ->
        Parent ! collect_timeout
    end.

%% Helper to receive data and track FIN flags
fin_receiver_loop(StreamRef, Parent) ->
    fin_receiver_loop(StreamRef, Parent, []).

fin_receiver_loop(StreamRef, Parent, Acc) ->
    receive
        {quic_dist_stream, StreamRef, {data, Data, Fin}} ->
            NewAcc = [{Data, Fin} | Acc],
            case Fin of
                true ->
                    Parent ! {fin_received, lists:reverse(NewAcc)};
                false ->
                    fin_receiver_loop(StreamRef, Parent, NewAcc)
            end;
        {quic_dist_stream, StreamRef, closed} ->
            Parent ! {fin_received, lists:reverse(Acc)}
    after 10000 ->
        Parent ! fin_timeout
    end.
