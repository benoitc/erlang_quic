%%% -*- erlang -*-
%%%
%%% quic_h3:close/2 closes the connection with an HTTP/3 error code: the
%%% peer receives the code in CONNECTION_CLOSE and the closing side's
%%% connection process exits `normal'.
%%%
%%% Server and client run in this VM over 127.0.0.1.
-module(quic_h3_close_code_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([peer_sees_the_error_code/1]).

%% H3_SETTINGS_ERROR (RFC 9114 Section 8.1).
-define(SETTINGS_ERROR, 16#109).
-define(WAIT_MS, 3000).

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [peer_sees_the_error_code].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    [{cert, Cert}, {key, Key} | Config].

end_per_suite(_Config) ->
    ok.

peer_sees_the_error_code(Config) ->
    Test = self(),
    Name = list_to_atom("h3_close_code_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun(Conn, _StreamId, _Method, _Path, _Headers) ->
            Mon = monitor(process, Conn),
            ok = quic_h3:close(Conn, ?SETTINGS_ERROR),
            receive
                {'DOWN', Mon, process, _, Reason} -> Test ! {server_exit, Reason}
            after ?WAIT_MS -> Test ! {server_exit, timeout}
            end
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{verify => false, sync => true}),
        %% What the client's QUIC connection reports to its H3 process.
        1 = erlang:trace(Conn, true, ['receive', {tracer, self()}]),
        {ok, _StreamId} = quic_h3:request(Conn, [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/">>},
            {<<":authority">>, <<"localhost">>}
        ]),
        receive
            {server_exit, Exit} -> ?assertEqual(normal, Exit)
        after ?WAIT_MS -> ct:fail(no_server_exit)
        end,
        ?assertMatch({peer_closed, application, ?SETTINGS_ERROR, _}, quic_closed_reason(Conn))
    after
        quic_h3:stop_server(Name)
    end.

quic_closed_reason(Conn) ->
    receive
        {trace, Conn, 'receive', {quic, _, {closed, Reason}}} -> Reason
    after ?WAIT_MS -> no_close
    end.
