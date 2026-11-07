%%% -*- erlang -*-
%%%
%%% quic_h3:close/2 closes the connection with an HTTP/3 error code: the
%%% peer's owner is told the code and the closing side's connection
%%% process exits `normal'. A plain close/1 still reads as `normal'.
%%%
%%% Server and client run in this VM over 127.0.0.1.
-module(quic_h3_close_code_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([peer_sees_the_error_code/1, clean_close_reads_normal/1]).

%% H3_SETTINGS_ERROR (RFC 9114 Section 8.1).
-define(SETTINGS_ERROR, 16#109).
-define(WAIT_MS, 3000).

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [peer_sees_the_error_code, clean_close_reads_normal].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    {Cert, Key} = quic_test_echo_server:cert_and_key(),
    [{cert, Cert}, {key, Key} | Config].

end_per_suite(_Config) ->
    ok.

peer_sees_the_error_code(Config) ->
    ?assertMatch(
        {peer_closed, application, ?SETTINGS_ERROR, _},
        server_closes(Config, fun(Conn) -> quic_h3:close(Conn, ?SETTINGS_ERROR) end)
    ).

clean_close_reads_normal(Config) ->
    ?assertEqual(normal, server_closes(Config, fun quic_h3:close/1)).

%% The reason the client's owner is given when the server's handler
%% closes the connection with Close.
server_closes(Config, Close) ->
    Test = self(),
    Name = list_to_atom("h3_close_code_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = quic_h3:start_server(Name, 0, #{
        cert => ?config(cert, Config),
        key => ?config(key, Config),
        handler => fun(Conn, _StreamId, _Method, _Path, _Headers) ->
            Mon = monitor(process, Conn),
            ok = Close(Conn),
            receive
                {'DOWN', Mon, process, _, Reason} -> Test ! {server_exit, Reason}
            after ?WAIT_MS -> Test ! {server_exit, timeout}
            end
        end
    }),
    {ok, Port} = quic:get_server_port(Name),
    try
        {ok, Conn} = quic_h3:connect("127.0.0.1", Port, #{verify => false, sync => true}),
        ClientMon = monitor(process, Conn),
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
        Reason = closed_reason(Conn),
        receive
            {'DOWN', ClientMon, process, _, ClientExit} -> ?assertEqual(normal, ClientExit)
        after ?WAIT_MS -> ct:fail(client_still_running)
        end,
        Reason
    after
        quic_h3:stop_server(Name)
    end.

closed_reason(Conn) ->
    receive
        {quic_h3, Conn, {closed, Reason}} -> Reason;
        {quic_h3, Conn, _} -> closed_reason(Conn)
    after ?WAIT_MS -> no_close
    end.
