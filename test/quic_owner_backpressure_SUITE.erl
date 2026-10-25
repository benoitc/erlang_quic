%%% -*- erlang -*-
%%%
%%% A peer can only send as fast as the connection's owner reads.
%%%
%%% Received stream data goes to the owner's mailbox. With `auto' credit
%%% the peer used to earn new credit as soon as a piece reached that
%%% mailbox, so an owner that stopped reading let a peer fill it until
%%% the VM ran out of memory. Credit now waits while the owner's mailbox
%%% holds more than `max_owner_queue' messages, and a `manual' stream
%%% earns it only for the bytes the owner returns with quic:consume/3.
%%%
%%% Each case sends far more than the bound to an owner that is not
%%% reading, checks what reached its mailbox, then lets it read and
%%% checks the whole transfer still arrives.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_owner_backpressure_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    auto_credit_follows_the_owner/1,
    manual_credit_follows_consume/1,
    max_owner_queue_is_validated/1
]).

-define(TOTAL, 32 * 1024 * 1024).
-define(CHUNK, 65536).
%% What the owner may be holding: its queue limit in full-size pieces
%% plus the windows granted before the limit was reached.
-define(BOUND, 3 * 1024 * 1024).
-define(WINDOW, 262144).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [
        auto_credit_follows_the_owner,
        manual_credit_follows_consume,
        max_owner_queue_is_validated
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

auto_credit_follows_the_owner(_Config) ->
    transfer(auto, #{}).

manual_credit_follows_consume(_Config) ->
    %% Only the stream's own credit holds the peer back here.
    transfer(manual, #{max_owner_queue => infinity}).

max_owner_queue_is_validated(_Config) ->
    ?assertEqual(
        {error, {invalid_max_owner_queue, 0}},
        quic:connect(<<"127.0.0.1">>, 4433, #{verify => false, max_owner_queue => 0}, self())
    ).

%%====================================================================
%% Helpers
%%====================================================================

transfer(Mode, Extra) ->
    Test = self(),
    {ok, Server} = quic_test_echo_server:start(Extra#{
        max_receive_window => ?WINDOW,
        max_data => ?WINDOW,
        max_stream_data_bidi_remote => ?WINDOW,
        connection_handler => fun(ConnPid, _ConnRef) ->
            {ok, spawn(fun() -> owner(Test, ConnPid, Mode) end)}
        end
    }),
    {ok, Conn} = quic:connect(
        <<"127.0.0.1">>, maps:get(port, Server), #{verify => false, alpn => [<<"echo">>]}, self()
    ),
    try
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> ct:fail(not_connected)
        end,
        {ok, StreamId} = quic:open_stream(Conn),
        Chunk = binary:copy(<<"x">>, ?CHUNK),
        [
            quic:send_data_async(Conn, StreamId, Chunk, false)
         || _ <- lists:seq(1, ?TOTAL div ?CHUNK - 1)
        ],
        quic:send_data_async(Conn, StreamId, Chunk, true),
        Owner =
            receive
                {owner, P} -> P
            after 5000 -> ct:fail(no_stream)
            end,
        Held = settle(Owner, 0, 0),
        ct:pal("~p: owner held ~p bytes", [Mode, Held]),
        ?assert(Held < ?BOUND),
        Owner ! read,
        receive
            {received, Total} -> ?assertEqual(?TOTAL, Total)
        after 60000 -> ct:fail(transfer_stalled)
        end
    after
        quic:close(Conn, normal),
        quic_test_echo_server:stop(Server)
    end.

%% The owner takes its stream, then stops reading until told to.
owner(Test, Conn, Mode) ->
    receive
        {quic, Conn, {stream_opened, StreamId}} ->
            case Mode of
                manual -> ok = quic:set_stream_flow_control(Conn, StreamId, manual);
                auto -> ok
            end,
            Test ! {owner, self()},
            receive
                read -> ok
            end,
            Test ! {received, read(Conn, StreamId, Mode, 0)}
    end.

read(Conn, StreamId, Mode, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            case Mode of
                manual -> ok = quic:consume(Conn, StreamId, byte_size(Data));
                auto -> ok
            end,
            case Fin of
                true -> Acc + byte_size(Data);
                false -> read(Conn, StreamId, Mode, Acc + byte_size(Data))
            end
    after 10000 -> Acc
    end.

%% Bytes in the owner's mailbox once they stop growing for a second.
settle(Owner, Last, Stable) when Stable >= 5 ->
    _ = Owner,
    Last;
settle(Owner, Last, Stable) ->
    timer:sleep(200),
    {messages, Msgs} = process_info(Owner, messages),
    Held = lists:sum([byte_size(D) || {quic, _, {stream_data, _, D, _}} <- Msgs]),
    case Held of
        Last -> settle(Owner, Held, Stable + 1);
        _ -> settle(Owner, Held, 0)
    end.
