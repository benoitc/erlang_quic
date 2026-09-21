%%% -*- erlang -*-
%%%
%%% QUIC Distribution User Stream Integration Tests
%%% Tests user stream functionality over QUIC distribution
%%%
%%% Both nodes are peers that speak QUIC distribution to each other; the
%%% test node is not one of them, so everything runs on the peers through
%%% peer:call/5 (see quic_dist_peer).
%%%
%%% Two things shape the cases. A stream belongs to the process that
%%% opened it and goes when that process does, while peer:call runs each
%%% call in a process of its own, so a node1 sequence that opens a stream
%%% and uses it runs inside one call. And incoming streams go round-robin
%%% to every registered acceptor, so each case's receiver leaves the pool
%%% before it reports, and the next case cannot hand its stream to it.
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

%% Run on the peers.
-export([
    start_receiver/2,
    receiver/2,
    first_data/0,
    echo/0,
    collect_hash/0,
    first_stream_id/0,
    collect_fin/0,
    exchange/4,
    open_and_close/1,
    open_many/2,
    send_after_close/1,
    owner_dies/1
]).

-define(CALL_MS, 90000).

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
    CertDir = filename:join(?config(priv_dir, Config), "certs"),
    {ok, Certs} = quic_dist_peer:generate_certs(CertDir),
    [{certs, Certs} | Config].

end_per_suite(_Config) ->
    ok.

init_per_group(two_node, Config) ->
    case quic_dist_peer:start("quic_ct_us", 2, ?config(certs, Config)) of
        {ok, [#{peer := Peer1, node := Node1} = P1, #{peer := Peer2, node := Node2} = P2]} ->
            pong = peer:call(Peer1, net_adm, ping, [Node2]),
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

%% Test opening a user stream
open_stream_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    {{ok, Stream}, Closed} = peer:call(Peer1, ?MODULE, open_and_close, [Node2], ?CALL_MS),
    ?assertMatch({quic_dist_stream, Node2, _}, Stream),
    {quic_dist_stream, _, StreamId} = Stream,
    %% User streams start above the ones distribution reserves.
    ?assert(StreamId >= 20),
    ?assertEqual(ok, Closed).

%% Test sending and receiving data
send_receive_test(Config) ->
    TestData = <<"Hello from user stream!">>,
    {_Stream, none, Result} = run(Config, first_data, [{TestData, false}], none),
    ?assertEqual({received, TestData}, Result).

%% Test bidirectional communication: node2 answers on the same stream,
%% and node1 has to get the answer.
bidirectional_test(Config) ->
    {_Stream, Echo, Result} = run(Config, echo, [{<<"Test">>, false}], echo),
    ?assertEqual(echoed, Result),
    ?assertEqual({echo, <<"Echo: Test">>}, Echo).

%% Test large data transfer: node2 hashes what arrived up to the FIN.
large_data_test(Config) ->
    LargeData = crypto:strong_rand_bytes(1024 * 1024),
    Hash = crypto:hash(sha256, LargeData),
    {_Stream, none, Result} = run(Config, collect_hash, [{LargeData, true}], none),
    ?assertEqual({collected, Hash}, Result).

%% Test multiple concurrent streams
multiple_streams_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    NumStreams = 10,
    Streams = peer:call(Peer1, ?MODULE, open_many, [Node2, NumStreams], ?CALL_MS),
    ?assertEqual(NumStreams, length(Streams)),
    StreamIds = [Id || {quic_dist_stream, _, Id} <- Streams],
    ?assertEqual(NumStreams, length(lists:usort(StreamIds))).

%% Test stream close: sending on a closed stream fails.
close_stream_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    ?assertMatch({error, _}, peer:call(Peer1, ?MODULE, send_after_close, [Node2], ?CALL_MS)).

%% Test owner death: the owner goes, and the connection is still usable
%% for the next stream.
owner_death_test(Config) ->
    {Peer1, _Node1, _Peer2, Node2} = pair(Config),
    ?assertMatch(
        {dead, {ok, {quic_dist_stream, Node2, _}}},
        peer:call(Peer1, ?MODULE, owner_dies, [Node2], ?CALL_MS)
    ).

%% Test accept_streams: the acceptor is given the stream node1 opened.
accept_streams_test(Config) ->
    {{quic_dist_stream, _, ExpectedId}, none, Result} =
        run(Config, first_stream_id, [{<<"trigger">>, false}], none),
    ?assertEqual({got_incoming, ExpectedId}, Result).

%% Test FIN flag semantics: data without FIN, then data with it.
fin_flag_test(Config) ->
    {_Stream, none, Result} = run(
        Config,
        collect_fin,
        [{<<"part1">>, false}, {<<"part2">>, false}, {<<"final">>, true}],
        none
    ),
    ?assertMatch({fin_received, [_ | _]}, Result),
    {fin_received, Chunks} = Result,
    ?assertEqual(<<"part1part2final">>, iolist_to_binary([D || {D, _} <- Chunks])),
    {_, LastFin} = lists:last(Chunks),
    ?assertEqual(true, LastFin).

%%====================================================================
%% Driving a case
%%====================================================================

%% Start a Kind receiver on node2, have node1 write Chunks to a new
%% stream, and return what node1 saw with what the receiver reports.
run(Config, Kind, Chunks, Wait) ->
    {Peer1, Node1, Peer2, Node2} = pair(Config),
    Receiver = peer:call(Peer2, ?MODULE, start_receiver, [Node1, Kind], ?CALL_MS),
    peer:call(Peer1, ?MODULE, exchange, [Node2, Receiver, Chunks, Wait], ?CALL_MS).

%%====================================================================
%% Run on node1
%%====================================================================

%% The stream stays open, owned by this process, until the receiver on
%% node2 has answered, and the answer comes back over distribution.
exchange(Node2, Receiver, Chunks, Wait) ->
    {ok, Stream} = quic_dist:open_stream(Node2),
    lists:foreach(fun({Data, Fin}) -> ok = quic_dist:send(Stream, Data, Fin) end, Chunks),
    Echo =
        case Wait of
            echo ->
                receive
                    {quic_dist_stream, Stream, {data, Data, _}} -> {echo, Data}
                after 10000 -> no_echo
                end;
            none ->
                none
        end,
    Receiver ! {get, self()},
    Result =
        receive
            {result, Receiver, R} -> R
        after 60000 -> result_timeout
        end,
    _ = quic_dist:close_stream(Stream),
    {Stream, Echo, Result}.

open_and_close(Node2) ->
    {ok, Stream} = quic_dist:open_stream(Node2),
    {{ok, Stream}, quic_dist:close_stream(Stream)}.

open_many(Node2, Count) ->
    Streams = [
        begin
            {ok, S} = quic_dist:open_stream(Node2),
            S
        end
     || _ <- lists:seq(1, Count)
    ],
    lists:foreach(fun(S) -> ok = quic_dist:close_stream(S) end, Streams),
    Streams.

send_after_close(Node2) ->
    {ok, Stream} = quic_dist:open_stream(Node2),
    ok = quic_dist:close_stream(Stream),
    quic_dist:send(Stream, <<"test">>).

owner_dies(Node2) ->
    Owner = spawn(fun() -> {ok, _} = quic_dist:open_stream(Node2) end),
    Ref = erlang:monitor(process, Owner),
    receive
        {'DOWN', Ref, process, Owner, _} -> ok
    after 5000 -> ok
    end,
    Dead =
        case is_process_alive(Owner) of
            false -> dead;
            true -> alive
        end,
    {Dead, quic_dist:open_stream(Node2)}.

%%====================================================================
%% Run on node2
%%====================================================================

start_receiver(Node1, Kind) ->
    {ok, Ctrl} = quic_dist:get_controller(Node1),
    Pid = spawn(?MODULE, receiver, [Ctrl, Kind]),
    ok = quic_dist_controller:accept_user_streams(Ctrl, Pid),
    Pid.

%% Do the work, leave the acceptor pool, then hold the outcome for
%% whoever asks for it.
receiver(Ctrl, Kind) ->
    Result = ?MODULE:Kind(),
    ok = quic_dist_controller:stop_accepting_streams(Ctrl),
    receive
        {get, From} -> From ! {result, self(), Result}
    after 60000 -> ok
    end.

first_data() ->
    receive
        {quic_dist_stream, _Ref, {data, Data, _Fin}} -> {received, Data}
    after 10000 -> timeout
    end.

echo() ->
    receive
        {quic_dist_stream, Ref, {data, Data, _}} ->
            ok = quic_dist:send(Ref, <<"Echo: ", Data/binary>>),
            echoed
    after 10000 -> timeout
    end.

collect_hash() ->
    receive
        {quic_dist_stream, Ref, {data, Data, Fin}} -> collect_hash(Ref, [Data], Fin)
    after 30000 -> no_incoming
    end.

collect_hash(_Ref, Acc, true) ->
    {collected, crypto:hash(sha256, lists:reverse(Acc))};
collect_hash(Ref, Acc, false) ->
    receive
        {quic_dist_stream, Ref, {data, Data, Fin}} -> collect_hash(Ref, [Data | Acc], Fin);
        {quic_dist_stream, Ref, closed} -> {collected, crypto:hash(sha256, lists:reverse(Acc))}
    after 30000 -> {partial, iolist_size(Acc)}
    end.

first_stream_id() ->
    receive
        {quic_dist_stream, {quic_dist_stream, _, StreamId}, {data, _, _}} ->
            {got_incoming, StreamId}
    after 10000 -> timeout
    end.

collect_fin() ->
    receive
        {quic_dist_stream, Ref, {data, Data, Fin}} -> collect_fin(Ref, [{Data, Fin}], Fin)
    after 10000 -> no_incoming
    end.

collect_fin(_Ref, Acc, true) ->
    {fin_received, lists:reverse(Acc)};
collect_fin(Ref, Acc, false) ->
    receive
        {quic_dist_stream, Ref, {data, Data, Fin}} -> collect_fin(Ref, [{Data, Fin} | Acc], Fin)
    after 10000 -> {no_fin, lists:reverse(Acc)}
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
