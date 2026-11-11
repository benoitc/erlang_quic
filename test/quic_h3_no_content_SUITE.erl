%%% -*- erlang -*-
%%%
%%% A response that carries a Content-Length but no body.
%%%
%%% RFC 9110 Section 8.6: the Content-Length on a response to HEAD states
%%% what the body would have been for a GET, and the response carries
%%% none. Section 6.4.1 says the same of 204 and 304. Reading that as a
%%% short body and resetting the stream with H3_MESSAGE_ERROR turns an
%%% ordinary HEAD into a failure.
%%%
%%% Server and client run in this VM over 127.0.0.1, the way hackney
%%% drives quic_h3, because the external servers the e2e suite talks to
%%% do not all put a Content-Length on a HEAD response, which is what
%%% let this through.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_h3_no_content_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    head_with_content_length/1,
    no_content_statuses_with_content_length/1,
    a_genuinely_short_body_is_still_refused/1,
    a_caller_supplied_status_is_not_duplicated/1,
    send_response_204_alone_ends_the_stream/1,
    many_204s_leave_no_stream_behind/1,
    no_content_responses_carry_no_data_frame/1,
    no_content_push_ends_on_headers/1,
    body_and_trailers_after_no_content_are_dropped/1,
    push_body_after_no_content_is_dropped/1
]).

-define(WAIT_MS, 3000).

%% The body a GET on /doc would return, and the Content-Length every
%% response below announces.
-define(DOC, <<"0123456789012345678901234567890123456789">>).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [
        head_with_content_length,
        no_content_statuses_with_content_length,
        a_genuinely_short_body_is_still_refused,
        a_caller_supplied_status_is_not_duplicated,
        send_response_204_alone_ends_the_stream,
        many_204s_leave_no_stream_behind,
        no_content_responses_carry_no_data_frame,
        no_content_push_ends_on_headers,
        body_and_trailers_after_no_content_are_dropped,
        push_body_after_no_content_is_dropped
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

%% The shape hackney hit: HEAD answered with the Content-Length a GET
%% would have had and an empty body.
head_with_content_length(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"HEAD">>, <<"/doc">>)),
        {response, StreamId, 200, RespHeaders} = next(Conn),
        %% One :status, not two. The server adds it and must not also
        %% pass through one the decoder already produced.
        ?assertEqual(
            1, length([V || {<<":status">>, V} <- RespHeaders])
        ),
        ?assertEqual({data, StreamId, <<>>, true}, next(Conn)),
        %% and the connection is still good for the next request
        {ok, Next} = quic_h3:request(Conn, headers(<<"GET">>, <<"/doc">>)),
        ?assertMatch({response, Next, 200, _}, next(Conn)),
        ?assertEqual({data, Next, ?DOC, true}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% 204 and 304 never carry content either, whatever they announce.
no_content_statuses_with_content_length(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        lists:foreach(
            fun(Path) ->
                {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, Path)),
                ?assertMatch({response, StreamId, _, _}, next(Conn)),
                ?assertEqual({data, StreamId, <<>>, true}, next(Conn))
            end,
            [<<"/204">>, <<"/304">>]
        ),
        quic_h3:close(Conn)
    end).

%% The check still does its job: a GET whose body really is shorter than
%% the Content-Length is a stream error.
a_genuinely_short_body_is_still_refused(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/short">>)),
        ?assertMatch({response, StreamId, 200, _}, next(Conn)),
        ?assertMatch({stream_reset, StreamId, _}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% send_response/4 takes the status as an argument, so a `:status' in the
%% header list is the same header twice, and two of one pseudo-header is
%% a malformed response.
a_caller_supplied_status_is_not_duplicated(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/dup-status">>)),
        {response, StreamId, 200, RespHeaders} = next(Conn),
        ?assertEqual(1, length([V || {<<":status">>, V} <- RespHeaders])),
        quic_h3:close(Conn)
    end).

%% RFC 9110 Section 6.4.1: a 204 is complete on its HEADERS, so
%% send_response/4 alone ends the stream.
send_response_204_alone_ends_the_stream(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/204-alone">>)),
        ?assertMatch({response, StreamId, 204, _}, next(Conn)),
        ?assertEqual({data, StreamId, <<>>, true}, next(Conn)),
        quic_h3:close(Conn)
    end).

%% Each of those streams is finished on the server, so none is left
%% holding a slot of the peer's stream limit.
many_204s_leave_no_stream_behind(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        lists:foreach(
            fun(_) ->
                {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/204-alone">>)),
                {response, StreamId, 204, _} = next(Conn),
                {data, StreamId, <<>>, true} = next(Conn)
            end,
            lists:seq(1, 250)
        ),
        {ok, Next} = quic_h3:request(Conn, headers(<<"GET">>, <<"/doc">>)),
        ?assertMatch({response, Next, 200, _}, next(Conn)),
        ?assertEqual({data, Next, ?DOC, true}, next(Conn)),
        {_, ServerState} = sys:get_state(server_conn()),
        ?assertEqual(#{}, quic_h3_connection:test_streams(ServerState)),
        quic_h3:close(Conn)
    end).

%% What the server writes on the request stream: the HEADERS frame with the
%% FIN, and no DATA frame, whichever call made the response.
no_content_responses_carry_no_data_frame(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        lists:foreach(
            fun({Method, Path}) ->
                {Wire, Events} = traced(Conn, Method, Path),
                ?assertMatch([[headers, fin]], Wire, {Method, Path}),
                ?assertMatch([{response, _, _, _}, {data, _, <<>>, true}], Events)
            end,
            [
                {<<"HEAD">>, <<"/doc">>},
                {<<"GET">>, <<"/204">>},
                {<<"GET">>, <<"/304">>},
                {<<"HEAD">>, <<"/respond">>},
                {<<"GET">>, <<"/respond-204">>},
                {<<"GET">>, <<"/respond-304">>}
            ]
        ),
        quic_h3:close(Conn)
    end).

%% A pushed 204 ends on its HEADERS too.
no_content_push_ends_on_headers(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        ok = quic_h3:set_max_push_id(Conn, 10),
        timer:sleep(100),
        {ok, StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/push-204">>)),
        Events = collect(Conn),
        ?assertMatch(
            [
                {push_stream, PushId, StreamId, _},
                {push_response, PushId, 204, _},
                {push_complete, PushId}
            ],
            [E || E <- Events, is_push_event(E)]
        ),
        quic_h3:close(Conn)
    end).

%% A body or trailers offered after a no-content response are not sent,
%% and the call still succeeds.
body_and_trailers_after_no_content_are_dropped(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        lists:foreach(
            fun({Method, Path}) ->
                _ = persistent_term:erase({?MODULE, result}),
                {Wire, Events} = traced(Conn, Method, Path),
                ?assertMatch([[headers, fin]], Wire, {Method, Path}),
                ?assertMatch([{response, _, _, _}, {data, _, <<>>, true}], Events),
                ?assertEqual(ok, handler_result())
            end,
            [
                {<<"GET">>, <<"/body-204">>},
                {<<"GET">>, <<"/body-304">>},
                {<<"HEAD">>, <<"/body-head">>},
                {<<"GET">>, <<"/trailers-204">>},
                {<<"HEAD">>, <<"/trailers-head">>}
            ]
        ),
        quic_h3:close(Conn)
    end).

push_body_after_no_content_is_dropped(Config) ->
    with_server(Config, fun(Port) ->
        Conn = connect(Port),
        ok = quic_h3:set_max_push_id(Conn, 10),
        timer:sleep(100),
        _ = persistent_term:erase({?MODULE, result}),
        {ok, _StreamId} = quic_h3:request(Conn, headers(<<"GET">>, <<"/push-204-body">>)),
        Events = [E || E <- collect(Conn), is_push_event(E)],
        ?assertMatch(
            [{push_stream, _, _, _}, {push_response, _, 204, _}, {push_complete, _}], Events
        ),
        ?assertEqual(ok, handler_result()),
        quic_h3:close(Conn)
    end).

%%====================================================================
%% Server
%%====================================================================

with_server(Config, F) ->
    Name = list_to_atom("h3_no_content_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun(Conn, StreamId, Method, Path, Headers) ->
            persistent_term:put({?MODULE, server_conn}, Conn),
            handle(Conn, StreamId, Method, Path, Headers)
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        F(Port)
    after
        quic_h3:stop_server(Name)
    end.

%% Every response announces the same Content-Length; what differs is
%% whether a body follows it.
handle(Conn, StreamId, <<"HEAD">>, <<"/doc">>, _Headers) ->
    respond(Conn, StreamId, 200, <<>>);
handle(Conn, StreamId, _Method, <<"/doc">>, _Headers) ->
    respond(Conn, StreamId, 200, ?DOC);
handle(Conn, StreamId, _Method, <<"/204">>, _Headers) ->
    respond(Conn, StreamId, 204, <<>>);
handle(Conn, StreamId, _Method, <<"/304">>, _Headers) ->
    respond(Conn, StreamId, 304, <<>>);
handle(Conn, StreamId, _Method, <<"/dup-status">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 200, [
        {<<":status">>, <<"200">>}, {<<"content-type">>, <<"text/plain">>}
    ]),
    ok = quic_h3:send_data(Conn, StreamId, <<>>, true);
handle(Conn, StreamId, _Method, <<"/short">>, _Headers) ->
    respond(Conn, StreamId, 200, <<"short">>);
handle(Conn, StreamId, _Method, <<"/204-alone">>, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, 204, []);
handle(Conn, StreamId, _Method, <<"/respond">>, _Headers) ->
    ok = quic_h3:respond(Conn, StreamId, 200, doc_headers(), ?DOC);
handle(Conn, StreamId, _Method, <<"/respond-204">>, _Headers) ->
    ok = quic_h3:respond(Conn, StreamId, 204, [], ?DOC);
handle(Conn, StreamId, _Method, <<"/respond-304">>, _Headers) ->
    ok = quic_h3:respond(Conn, StreamId, 304, doc_headers(), ?DOC);
handle(Conn, StreamId, _Method, <<"/push-204">>, _Headers) ->
    {ok, PushId} = quic_h3:push(Conn, StreamId, headers(<<"GET">>, <<"/pushed">>)),
    ok = quic_h3:send_push_response(Conn, PushId, 204, []),
    ok = quic_h3:respond(Conn, StreamId, 200, [], <<"page">>);
handle(Conn, StreamId, _Method, <<"/push-204-body">>, _Headers) ->
    {ok, PushId} = quic_h3:push(Conn, StreamId, headers(<<"GET">>, <<"/pushed">>)),
    ok = quic_h3:send_push_response(Conn, PushId, 204, []),
    result(quic_h3:send_push_data(Conn, PushId, <<"oops">>, true)),
    ok = quic_h3:respond(Conn, StreamId, 200, [], <<"page">>);
handle(Conn, StreamId, _Method, <<"/body-", _/binary>> = Path, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, path_status(Path), [{<<"content-length">>, <<"4">>}]),
    result(quic_h3:send_data(Conn, StreamId, <<"oops">>, true));
handle(Conn, StreamId, _Method, <<"/trailers-", _/binary>> = Path, _Headers) ->
    ok = quic_h3:send_response(Conn, StreamId, path_status(Path), []),
    result(quic_h3:send_trailers(Conn, StreamId, [{<<"x-trailer">>, <<"t">>}]));
handle(Conn, StreamId, _Method, _Path, _Headers) ->
    respond(Conn, StreamId, 404, <<>>).

path_status(Path) ->
    case binary:split(Path, <<"-">>) of
        [_, <<"head">>] -> 200;
        [_, Status] -> binary_to_integer(Status)
    end.

%% What the handler's last send call returned, for the test to check.
result(Result) ->
    persistent_term:put({?MODULE, result}, Result).

handler_result() ->
    persistent_term:get({?MODULE, result}, none).

doc_headers() ->
    [
        {<<"content-type">>, <<"text/plain">>},
        {<<"content-length">>, integer_to_binary(byte_size(?DOC))}
    ].

server_conn() ->
    persistent_term:get({?MODULE, server_conn}).

respond(Conn, StreamId, Status, Body) ->
    Headers = [
        {<<"content-type">>, <<"text/plain">>},
        {<<"content-length">>, integer_to_binary(byte_size(?DOC))}
    ],
    ok = quic_h3:send_response(Conn, StreamId, Status, Headers),
    ok = quic_h3:send_data(Conn, StreamId, Body, true).

%%====================================================================
%% Client
%%====================================================================

connect(Port) ->
    {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{verify => false, sync => true}),
    Conn.

headers(Method, Path) ->
    [
        {<<":method">>, Method},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, Path},
        {<<":authority">>, <<"localhost">>}
    ].

%% The next stream event the client connection reports.
next(Conn) ->
    receive
        {quic_h3, Conn, {settings, _}} -> next(Conn);
        {quic_h3, Conn, {goaway, _}} -> next(Conn);
        {quic_h3, Conn, {session_ticket, _}} -> next(Conn);
        {quic_h3, Conn, {early_data_rejected, _}} -> next(Conn);
        {quic_h3, Conn, Event} -> Event
    after ?WAIT_MS -> heard_nothing
    end.

%% Every event until the connection is quiet.
collect(Conn) ->
    case next(Conn) of
        heard_nothing -> [];
        Event -> [Event | collect(Conn)]
    end.

is_push_event(Event) ->
    lists:member(element(1, Event), [push_stream, push_response, push_data, push_complete]).

%%====================================================================
%% Wire trace
%%====================================================================

%% The request, the client events, and the HTTP/3 frames the server wrote
%% on the request stream, one list per quic:send_data/4 call.
traced(Conn, Method, Path) ->
    Self = self(),
    Tracer = spawn(fun() -> tracer_loop(Self, []) end),
    erlang:trace(all, true, [call, {tracer, Tracer}]),
    erlang:trace_pattern({quic, send_data, 4}, true, [global]),
    {ok, StreamId} = quic_h3:request(Conn, headers(Method, Path)),
    Events = collect(Conn),
    erlang:trace(all, false, [call]),
    erlang:trace_pattern({quic, send_data, 4}, false, [global]),
    Tracer ! {done, Self},
    Calls =
        receive
            {calls, Tracer, C} -> C
        after ?WAIT_MS -> error(no_trace)
        end,
    Wire = [
        frames(iolist_to_binary(Data), Fin)
     || {Pid, [_Q, Sid, Data, Fin]} <- Calls, Sid =:= StreamId, Pid =/= Conn
    ],
    {Wire, Events}.

tracer_loop(Owner, Acc) ->
    receive
        {trace, Pid, call, {quic, send_data, Args}} -> tracer_loop(Owner, [{Pid, Args} | Acc]);
        {done, Owner} -> Owner ! {calls, self(), lists:reverse(Acc)};
        _ -> tracer_loop(Owner, Acc)
    end.

frames(<<>>, true) ->
    [fin];
frames(<<>>, false) ->
    [];
frames(Bin, Fin) ->
    {ok, Frame, Rest} = quic_h3_frame:decode(Bin),
    [element(1, Frame) | frames(Rest, Fin)].
