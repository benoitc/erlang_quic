%%% -*- erlang -*-
%%%
%%% Session resumption on one scheduler.
%%%
%%% A client resuming with a session ticket derives early keys, and its
%%% HTTP/3 layer opens the control and QPACK streams as 0-RTT data. On
%%% one scheduler the QUIC connection often reads the server's first
%%% packets before the HTTP/3 layer gets to run, so those streams have to
%%% open in the `handshaking' state too, not only in `idle'. They did
%%% not, and the resumed connect ended in connect_timeout.
%%%
%%% Each case runs its loop with one scheduler online, the way
%%% ERL_FLAGS="+S 1:1" runs a whole VM, and restores the count after.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_resumption_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("quic/include/quic.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([
    a_resumed_connection_issues_a_new_ticket/1,
    resumption_with_early_data_on_one_scheduler/1,
    resumption_without_early_data_on_one_scheduler/1
]).

-define(ROUNDS, 50).
%% A loopback resumption takes a few milliseconds; this is far inside
%% the handshake's own probe timeouts, so a stall shows as a failure.
-define(ROUND_MS, 2000).

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [
        a_resumed_connection_issues_a_new_ticket,
        resumption_with_early_data_on_one_scheduler,
        resumption_without_early_data_on_one_scheduler
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, Server} = quic_test_h3_server:start(),
    [{server, Server} | Config].

end_per_suite(Config) ->
    quic_test_h3_server:stop(?config(server, Config)).

init_per_testcase(a_resumed_connection_issues_a_new_ticket, Config) ->
    Config;
init_per_testcase(_Case, Config) ->
    [{schedulers, erlang:system_flag(schedulers_online, 1)} | Config].

end_per_testcase(a_resumed_connection_issues_a_new_ticket, _Config) ->
    ok;
end_per_testcase(_Case, Config) ->
    erlang:system_flag(schedulers_online, ?config(schedulers, Config)),
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% Tickets are single-use, so a client resumes again only with the ticket
%% its resumed connection issued. On all schedulers, apart from the
%% single-scheduler cases below.
a_resumed_connection_issues_a_new_ticket(Config) ->
    Port = port(Config),
    {ok, First} = connect(Port, #{}),
    {ok, Ticket} = request_and_ticket(First),
    quic_h3:close(First),
    {ok, Resumed} = connect(Port, #{session_ticket => Ticket}),
    Result = request_and_ticket(Resumed),
    quic_h3:close(Resumed),
    ?assertMatch({ok, #session_ticket{}}, Result).

%% Every round resumes with the ticket the previous connection issued,
%% sends its request as 0-RTT, and the server accepts it.
resumption_with_early_data_on_one_scheduler(Config) ->
    Port = port(Config),
    Rounds = rounds(Port, fun(Ticket) -> Ticket end),
    ?assertEqual([], [X || {_, R} = X <- Rounds, R =/= {ok, true}]).

%% A ticket without early data: every round resumes in 1-RTT.
resumption_without_early_data_on_one_scheduler(Config) ->
    Port = port(Config),
    Rounds = rounds(Port, fun(Ticket) -> Ticket#session_ticket{max_early_data = 0} end),
    ?assertEqual([], [X || {_, R} = X <- Rounds, R =/= {ok, false}]).

%%====================================================================
%% Helpers
%%====================================================================

port(Config) ->
    maps:get(port, ?config(server, Config)).

%% ?ROUNDS resumptions in a row, each with the ticket from the round
%% before passed through Prepare. Returns {Round, Result} for each.
rounds(Port, Prepare) ->
    {ok, Conn} = connect(Port, #{}),
    {ok, Ticket} = request_and_ticket(Conn),
    quic_h3:close(Conn),
    rounds(1, Port, Prepare, Ticket, []).

rounds(N, _Port, _Prepare, _Ticket, Acc) when N > ?ROUNDS ->
    lists:reverse(Acc);
rounds(N, Port, Prepare, Ticket, Acc) ->
    case connect(Port, #{session_ticket => Prepare(Ticket)}) of
        {ok, Conn} ->
            Early = quic_h3:early_data_accepted(Conn),
            Result = request_and_ticket(Conn),
            quic_h3:close(Conn),
            case Result of
                {ok, Next} -> rounds(N + 1, Port, Prepare, Next, [{N, {ok, Early}} | Acc]);
                Failed -> lists:reverse([{N, Failed} | Acc])
            end;
        Failed ->
            lists:reverse([{N, Failed} | Acc])
    end.

connect(Port, QuicOpts) ->
    quic_h3:connect("127.0.0.1", Port, #{
        verify => false, sync => true, connect_timeout => ?ROUND_MS, quic_opts => QuicOpts
    }).

%% One GET answered in full, and the session ticket the connection issued.
request_and_ticket(Conn) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    Deadline = erlang:monotonic_time(millisecond) + ?ROUND_MS,
    case quic_h3:request(Conn, Headers) of
        {ok, StreamId} -> await(Conn, StreamId, Deadline, undefined, false);
        Error -> {request_failed, Error}
    end.

await(_Conn, _StreamId, _Deadline, Ticket, true) when Ticket =/= undefined ->
    {ok, Ticket};
await(Conn, StreamId, Deadline, Ticket, Done) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {quic_h3, Conn, {session_ticket, T}} -> await(Conn, StreamId, Deadline, T, Done);
        {quic_h3, Conn, {data, StreamId, _, true}} -> await(Conn, StreamId, Deadline, Ticket, true);
        {quic_h3, Conn, {stream_reset, StreamId, _} = Reset} -> Reset;
        {quic_h3, Conn, {error, _} = Error} -> Error
    after Left ->
        {stalled, #{response_done => Done, ticket => Ticket =/= undefined}}
    end.
