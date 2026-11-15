%%% -*- erlang -*-
%%%
%%% A stream_type_handler can claim a stream with manual receive credit:
%%% `{claim, #{flow_control => manual}}'. quic_h3 then never runs the
%%% stream on `auto': the peer gets one stream window past what the owner
%%% has consumed with quic_h3:consume/3, however late the owner is. Plain
%%% `claim' keeps today's behaviour (credit follows delivery).
%%%
%%% Server and client run in this VM over 127.0.0.1.
-module(quic_h3_claimed_stream_credit_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    busy_owner_of_manual_bidi_claim_holds_peer_to_one_window/1,
    busy_owner_of_manual_uni_claim_holds_peer_to_one_window/1,
    owner_that_consumes_a_manual_claim_gets_everything/1,
    manual_bidi_stream_we_open_holds_peer_to_one_window/1
]).

-define(WT_STREAM, 16#41).
-define(WT_UNI_STREAM, 16#54).
%% DEFAULT_INITIAL_MAX_STREAM_DATA.
-define(WINDOW, 524288).
-define(OFFERED, 8 * 1048576).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        busy_owner_of_manual_bidi_claim_holds_peer_to_one_window,
        busy_owner_of_manual_uni_claim_holds_peer_to_one_window,
        owner_that_consumes_a_manual_claim_gets_everything,
        manual_bidi_stream_we_open_holds_peer_to_one_window
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    [{cert, Cert}, {key, Key} | Config].

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% The owner takes 1 s to get to its mailbox, as a busy one would, and
%% never consumes. The client offers 8 MiB on a bidi stream. The owner
%% gets about one stream window: enough to show the stream was claimed
%% and credited, and no more.
busy_owner_of_manual_bidi_claim_holds_peer_to_one_window(Config) ->
    {Claimed, Received} = run(Config, bidi, #{busy_ms => 1000, consume => false}, 3000),
    ct:pal("bidi: owner received ~p bytes on a ~p byte window", [Received, ?WINDOW]),
    ?assert(Claimed),
    ?assert(Received >= ?WINDOW div 2),
    ?assert(Received =< ?WINDOW + 16).

busy_owner_of_manual_uni_claim_holds_peer_to_one_window(Config) ->
    {Claimed, Received} = run(Config, uni, #{busy_ms => 1000, consume => false}, 3000),
    ct:pal("uni: owner received ~p bytes on a ~p byte window", [Received, ?WINDOW]),
    ?assert(Claimed),
    ?assert(Received >= ?WINDOW div 2),
    ?assert(Received =< ?WINDOW + 16).

%% The stream type is credited by quic_h3 and the payload by the owner, so
%% an owner that consumes every chunk is never left short of credit.
owner_that_consumes_a_manual_claim_gets_everything(Config) ->
    {Claimed, Received} = run(Config, bidi, #{busy_ms => 0, consume => true}, 10000),
    ?assert(Claimed),
    ?assertEqual(?OFFERED, Received).

%% The client opens a pre-claimed bidi stream with manual credit and does
%% not read for 3 s while the server writes 8 MiB on it. Everything the
%% server sends is payload, so the client gets one window and no more.
manual_bidi_stream_we_open_holds_peer_to_one_window(Config) ->
    Writer = spawn_link(fun writer/0),
    Name = list_to_atom("h3_csc_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        settings => #{enable_connect_protocol => 1},
        stream_type_handler => fun claim_manual/3,
        handler => fun(_C, _S, _M, _P, _H) -> ok end,
        connection_handler => fun(_Conn) -> #{owner => Writer} end
    }),
    {ok, Port} = quic:get_server_port(Name),
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{
        verify => false,
        sync => true,
        settings => #{enable_connect_protocol => 1}
    }),
    try
        QC = quic_h3:get_quic_conn(Conn),
        {ok, StreamId} = quic_h3:open_bidi_stream(Conn, ?WT_STREAM, #{flow_control => manual}),
        ok = quic:send_data(QC, StreamId, <<16#40, ?WT_STREAM, 0>>, false),
        timer:sleep(3000),
        Received = received(Conn, StreamId, 0),
        ct:pal("open_bidi_stream/3: client received ~p bytes on a ~p byte window", [
            Received, ?WINDOW
        ]),
        ?assert(Received >= ?WINDOW div 2),
        ?assert(Received =< ?WINDOW)
    after
        quic_h3:close(Conn),
        quic_h3:stop_server(Name),
        unlink(Writer),
        exit(Writer, kill)
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% Offers 8 MiB on a claimed stream of the given direction, then reports
%% whether the server's owner saw the stream claimed and how many payload
%% bytes it received after WaitMs.
run(Config, Direction, OwnerOpts, WaitMs) ->
    Owner = spawn_link(fun() -> owner(OwnerOpts) end),
    Name = list_to_atom("h3_csc_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        settings => #{enable_connect_protocol => 1},
        stream_type_handler => fun claim_manual/3,
        handler => fun(_C, _S, _M, _P, _H) -> ok end,
        connection_handler => fun(_Conn) -> #{owner => Owner} end
    }),
    {ok, Port} = quic:get_server_port(Name),
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{
        verify => false,
        sync => true,
        settings => #{enable_connect_protocol => 1},
        stream_type_handler => fun claim_manual/3
    }),
    try
        QC = quic_h3:get_quic_conn(Conn),
        StreamId = open(Conn, QC, Direction),
        Sender = spawn_link(fun() -> send_chunks(QC, StreamId, ?OFFERED div 65536) end),
        Result = wait_total(Owner, WaitMs),
        unlink(Sender),
        exit(Sender, kill),
        Result
    after
        quic_h3:close(Conn),
        quic_h3:stop_server(Name),
        unlink(Owner),
        exit(Owner, kill)
    end.

%% The stream header is the type and a one-byte session id (0), so the
%% payload starts at the same offset on both kinds of stream.
open(Conn, QC, bidi) ->
    {ok, StreamId} = quic_h3:open_bidi_stream(Conn, ?WT_STREAM),
    ok = quic:send_data(QC, StreamId, <<16#40, ?WT_STREAM>>, false),
    StreamId;
open(Conn, _QC, uni) ->
    {ok, StreamId} = quic_h3:open_uni_stream(Conn, ?WT_UNI_STREAM),
    StreamId.

claim_manual(bidi, _StreamId, ?WT_STREAM) -> {claim, #{flow_control => manual}};
claim_manual(uni, _StreamId, ?WT_UNI_STREAM) -> {claim, #{flow_control => manual}};
claim_manual(_Dir, _StreamId, _Type) -> ignore.

owner(#{busy_ms := BusyMs} = Opts) ->
    timer:sleep(BusyMs),
    owner_loop(Opts, false, 0).

owner_loop(Opts, Claimed, Total) ->
    receive
        {quic_h3, _H3, {stream_type_open, _Dir, _StreamId, _Type}} ->
            owner_loop(Opts, true, Total);
        {quic_h3, H3, {stream_type_data, _Dir, StreamId, Data, _Fin}} ->
            case Opts of
                #{consume := true} -> ok = quic_h3:consume(H3, StreamId, byte_size(Data));
                _ -> ok
            end,
            owner_loop(Opts, Claimed, Total + byte_size(Data));
        {total, From} ->
            From ! {total, Claimed, Total},
            owner_loop(Opts, Claimed, Total);
        _ ->
            owner_loop(Opts, Claimed, Total)
    end.

%% The session id byte (0) is payload to quic_h3, so it is not counted.
wait_total(Owner, WaitMs) ->
    timer:sleep(WaitMs),
    Owner ! {total, self()},
    receive
        {total, Claimed, Total} -> {Claimed, max(0, Total - 1)}
    after 5000 -> error(no_total)
    end.

%% A one-byte session id, then 64 KiB at a time, waiting while the send
%% queue is full.
send_chunks(QC, StreamId, N) ->
    ok = quic:send_data(QC, StreamId, <<0>>, false),
    send_loop(QC, StreamId, N).

send_loop(_QC, _StreamId, 0) ->
    ok;
send_loop(QC, StreamId, N) ->
    case quic:send_data(QC, StreamId, binary:copy(<<1>>, 65536), false) of
        ok ->
            send_loop(QC, StreamId, N - 1);
        {error, _} ->
            timer:sleep(5),
            send_loop(QC, StreamId, N)
    end.

%% The server's owner writes 8 MiB on each bidi stream the client opens.
writer() ->
    receive
        {quic_h3, H3, {stream_type_open, bidi, StreamId, ?WT_STREAM}} ->
            QC = quic_h3:get_quic_conn(H3),
            _ = spawn_link(fun() -> send_loop(QC, StreamId, ?OFFERED div 65536) end),
            writer();
        _ ->
            writer()
    end.

%% Payload bytes the client's owner (this process) has been sent so far.
received(Conn, StreamId, Total) ->
    receive
        {quic_h3, Conn, {stream_type_data, bidi, StreamId, Data, _Fin}} ->
            received(Conn, StreamId, Total + byte_size(Data))
    after 0 ->
        Total
    end.
