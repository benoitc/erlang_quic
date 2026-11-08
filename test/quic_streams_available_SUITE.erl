%%% -*- erlang -*-
%%%
%%% With notify_streams_available, an owner whose open was refused with
%%% stream_limit is told once when the peer's MAX_STREAMS lets it open
%%% again, instead of polling: {quic, Conn, {streams_available, Dir}}, and
%%% {quic_h3, Conn, {streams_available, bidi}} through quic_h3. Without the
%%% option nothing is sent.
%%%
%%% Servers and clients run in this VM over 127.0.0.1. A peer stream the
%%% echo server has finished both ways is given back as MAX_STREAMS.
-module(quic_streams_available_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    refused_bidi_open_is_told_when_streams_return/1,
    nothing_without_the_option/1,
    nothing_without_a_refusal/1,
    one_message_per_refusal_episode/1,
    refused_uni_open_is_told_when_streams_return/1,
    quic_h3_owner_is_told/1,
    quic_h3_owner_is_not_told_after_goaway/1,
    quic_h3_uni_open_is_told/1,
    quic_h3_bidi_open_after_goaway_is_told/1,
    quic_h3_nothing_without_the_option/1
]).

-define(WAIT_MS, 3000).
-define(QUIET_MS, 300).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        refused_bidi_open_is_told_when_streams_return,
        nothing_without_the_option,
        nothing_without_a_refusal,
        one_message_per_refusal_episode,
        refused_uni_open_is_told_when_streams_return,
        quic_h3_owner_is_told,
        quic_h3_owner_is_not_told_after_goaway,
        quic_h3_uni_open_is_told,
        quic_h3_bidi_open_after_goaway_is_told,
        quic_h3_nothing_without_the_option
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    [{cert, Cert}, {key, Key} | Config].

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Raw QUIC
%%====================================================================

refused_bidi_open_is_told_when_streams_return(_Config) ->
    with_conn(#{notify_streams_available => true}, fun(Conn) ->
        [S1, S2] = [open(Conn) || _ <- [1, 2]],
        ?assertEqual({error, stream_limit}, quic:open_stream(Conn)),
        ok = finish(Conn, S1),
        ok = finish(Conn, S2),
        ?assertEqual({streams_available, bidi}, available(Conn)),
        ?assertMatch({ok, _}, quic:open_stream(Conn)),
        ?assertEqual(none, available(Conn, ?QUIET_MS))
    end).

nothing_without_the_option(_Config) ->
    with_conn(#{}, fun(Conn) ->
        [S1, S2] = [open(Conn) || _ <- [1, 2]],
        ?assertEqual({error, stream_limit}, quic:open_stream(Conn)),
        ok = finish(Conn, S1),
        ok = finish(Conn, S2),
        ?assertEqual(none, available(Conn, ?QUIET_MS)),
        ?assertMatch({ok, _}, quic:open_stream(Conn))
    end).

%% MAX_STREAMS keeps arriving, but no open was refused.
nothing_without_a_refusal(_Config) ->
    with_conn(#{notify_streams_available => true}, fun(Conn) ->
        lists:foreach(fun(_) -> ok = finish(Conn, open(Conn)) end, lists:seq(1, 4)),
        ?assertEqual(none, available(Conn, ?QUIET_MS))
    end).

%% Two refusals before the credit returns are one episode; a refusal after
%% the message starts a new one.
one_message_per_refusal_episode(_Config) ->
    with_conn(#{notify_streams_available => true}, fun(Conn) ->
        [S1, S2] = [open(Conn) || _ <- [1, 2]],
        ?assertEqual({error, stream_limit}, quic:open_stream(Conn)),
        ?assertEqual({error, stream_limit}, quic:open_stream(Conn)),
        ok = finish(Conn, S1),
        ok = finish(Conn, S2),
        ?assertEqual({streams_available, bidi}, available(Conn)),
        ?assertEqual(none, available(Conn, ?QUIET_MS)),
        [S3, S4] = [open(Conn) || _ <- [1, 2]],
        ?assertEqual({error, stream_limit}, quic:open_stream(Conn)),
        ok = finish(Conn, S3),
        ok = finish(Conn, S4),
        ?assertEqual({streams_available, bidi}, available(Conn))
    end).

refused_uni_open_is_told_when_streams_return(_Config) ->
    with_conn(#{notify_streams_available => true}, fun(Conn) ->
        {ok, U1} = quic:open_unidirectional_stream(Conn),
        {ok, U2} = quic:open_unidirectional_stream(Conn),
        ?assertEqual({error, stream_limit}, quic:open_unidirectional_stream(Conn)),
        ok = quic:send_data(Conn, U1, <<"x">>, true),
        ok = quic:send_data(Conn, U2, <<"x">>, true),
        ?assertEqual({streams_available, uni}, available(Conn)),
        ?assertMatch({ok, _}, quic:open_unidirectional_stream(Conn))
    end).

%%====================================================================
%% quic_h3
%%====================================================================

quic_h3_owner_is_told(Config) ->
    with_h3(Config, fun(Conn) ->
        [S1, S2] = [request(Conn) || _ <- [1, 2]],
        ?assertEqual(
            {error, stream_limit}, quic_h3:request(Conn, headers(), #{end_stream => false})
        ),
        ok = h3_finish(Conn, S1),
        ok = h3_finish(Conn, S2),
        ?assertEqual({streams_available, bidi}, h3_available(Conn, ?WAIT_MS))
    end).

%% Once the server has sent GOAWAY no new request can open, so the owner
%% is not told.
quic_h3_owner_is_not_told_after_goaway(Config) ->
    with_h3(Config, fun(Conn) ->
        [S1, S2] = [request(Conn) || _ <- [1, 2]],
        ?assertEqual(
            {error, stream_limit}, quic_h3:request(Conn, headers(), #{end_stream => false})
        ),
        ServerConn = await(server_h3),
        ok = quic_h3:goaway(ServerConn),
        receive
            {quic_h3, Conn, {goaway, _}} -> ok
        after ?WAIT_MS -> ct:fail(no_goaway)
        end,
        ok = h3_finish(Conn, S1),
        ok = h3_finish(Conn, S2),
        ?assertEqual(none, h3_available(Conn, ?QUIET_MS))
    end).

%% The client's own control and QPACK streams take 3 of the 5 uni streams
%% the server allows, so the owner can open 2.
quic_h3_uni_open_is_told(Config) ->
    with_h3(Config, #{notify_streams_available => true}, fun(Conn) ->
        QC = quic_h3:get_quic_conn(Conn),
        {ok, U1} = quic_h3:open_uni_stream(Conn, 16#54),
        {ok, U2} = quic_h3:open_uni_stream(Conn, 16#54),
        ?assertEqual({error, stream_limit}, quic_h3:open_uni_stream(Conn, 16#54)),
        ok = quic:send_data(QC, U1, <<0>>, true),
        ok = quic:send_data(QC, U2, <<0>>, true),
        ?assertEqual({streams_available, uni}, h3_available(Conn, ?WAIT_MS)),
        ?assertMatch({ok, _}, quic_h3:open_uni_stream(Conn, 16#54))
    end).

%% A stream the owner opens itself can still open after GOAWAY, so its
%% refusal is told then.
quic_h3_bidi_open_after_goaway_is_told(Config) ->
    with_h3(Config, #{notify_streams_available => true}, fun(Conn) ->
        [S1, S2] = [request(Conn) || _ <- [1, 2]],
        ServerConn = await(server_h3),
        ok = quic_h3:goaway(ServerConn),
        receive
            {quic_h3, Conn, {goaway, _}} -> ok
        after ?WAIT_MS -> ct:fail(no_goaway)
        end,
        ?assertEqual({error, stream_limit}, quic_h3:open_bidi_stream(Conn, 16#41)),
        ok = h3_finish(Conn, S1),
        ok = h3_finish(Conn, S2),
        ?assertEqual({streams_available, bidi}, h3_available(Conn, ?WAIT_MS))
    end).

quic_h3_nothing_without_the_option(Config) ->
    with_h3(Config, #{}, fun(Conn) ->
        QC = quic_h3:get_quic_conn(Conn),
        {ok, U1} = quic_h3:open_uni_stream(Conn, 16#54),
        {ok, U2} = quic_h3:open_uni_stream(Conn, 16#54),
        ?assertEqual({error, stream_limit}, quic_h3:open_uni_stream(Conn, 16#54)),
        [S1, S2] = [request(Conn) || _ <- [1, 2]],
        ?assertEqual({error, stream_limit}, quic_h3:open_bidi_stream(Conn, 16#41)),
        ok = quic:send_data(QC, U1, <<0>>, true),
        ok = quic:send_data(QC, U2, <<0>>, true),
        ok = h3_finish(Conn, S1),
        ok = h3_finish(Conn, S2),
        ?assertEqual(none, h3_available(Conn, ?QUIET_MS))
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% A client to an echo server that allows 2 streams of each kind.
with_conn(ClientExtra, F) ->
    {ok, Server} = quic_test_echo_server:start(#{max_streams_bidi => 2, max_streams_uni => 2}),
    Opts = maps:merge(quic_test_echo_server:client_opts(), ClientExtra#{alpn => [<<"echo">>]}),
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, maps:get(port, Server), Opts, self()),
    try
        receive
            {quic, Conn, {connected, _}} -> ok
        after ?WAIT_MS -> ct:fail(connect_timeout)
        end,
        F(Conn)
    after
        quic:safe_close(Conn),
        quic_test_echo_server:stop(Server)
    end.

open(Conn) ->
    {ok, StreamId} = quic:open_stream(Conn),
    StreamId.

%% Finish a stream both ways: our FIN, then the echo's.
finish(Conn, StreamId) ->
    ok = quic:send_data(Conn, StreamId, <<"x">>, true),
    await_fin(Conn, StreamId).

await_fin(Conn, StreamId) ->
    receive
        {quic, Conn, {stream_data, StreamId, _, true}} -> ok;
        {quic, Conn, {stream_data, StreamId, _, false}} -> await_fin(Conn, StreamId)
    after ?WAIT_MS -> {no_fin, StreamId}
    end.

available(Conn) ->
    available(Conn, ?WAIT_MS).

available(Conn, Timeout) ->
    receive
        {quic, Conn, {streams_available, _} = E} -> E
    after Timeout -> none
    end.

%% A quic_h3 client with the option, to a server allowing 2 requests at
%% once whose handler waits for the whole request and then answers.
with_h3(Config, F) ->
    with_h3(Config, #{notify_streams_available => true}, F).

%% ClientOpts are merged into the client's connect options.
with_h3(Config, ClientOpts, F) ->
    Test = self(),
    Name = list_to_atom("h3_sa_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        quic_opts => #{max_streams_bidi => 2, max_streams_uni => 5},
        notify_streams_available => true,
        handler => fun(C, S, _M, _P, _H) ->
            Test ! {server_h3, C},
            %% The body's end may already be among the buffered chunks.
            case quic_h3:set_stream_handler(C, S, self()) of
                {ok, Chunks} when Chunks =/= [] ->
                    case lists:last(Chunks) of
                        {_, true} -> ok;
                        _ -> await_body_end(C, S)
                    end;
                _ ->
                    await_body_end(C, S)
            end,
            quic_h3:respond(C, S, 200, [], <<"ok">>)
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, ClientOpts#{verify => false, sync => true}),
    try
        F(Conn)
    after
        quic_h3:close(Conn),
        quic_h3:stop_server(Name)
    end.

await_body_end(C, S) ->
    receive
        {quic_h3, C, {data, S, _, true}} -> ok;
        {quic_h3, C, {data, S, _, false}} -> await_body_end(C, S)
    after ?WAIT_MS -> ok
    end.

headers() ->
    [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<":path">>, <<"/">>}
    ].

request(Conn) ->
    {ok, StreamId} = quic_h3:request(Conn, headers(), #{end_stream => false}),
    StreamId.

%% End the request body and wait for the whole response.
h3_finish(Conn, StreamId) ->
    ok = quic_h3:send_data(Conn, StreamId, <<>>, true),
    h3_await_end(Conn, StreamId).

h3_await_end(Conn, StreamId) ->
    receive
        {quic_h3, Conn, {data, StreamId, _, true}} -> ok;
        {quic_h3, Conn, {data, StreamId, _, false}} -> h3_await_end(Conn, StreamId);
        {quic_h3, Conn, {response, StreamId, _, _}} -> h3_await_end(Conn, StreamId)
    after ?WAIT_MS -> {no_end, StreamId}
    end.

h3_available(Conn, Timeout) ->
    receive
        {quic_h3, Conn, {streams_available, _} = E} -> E
    after Timeout -> none
    end.

await(Tag) ->
    receive
        {Tag, Value} -> Value
    after ?WAIT_MS -> ct:fail({no, Tag})
    end.
