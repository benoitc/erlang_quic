%%% -*- erlang -*-
%%%
%%% A session ticket resumes only where it was issued.
%%%
%%% A server keeps the tickets it issues so a later connection can
%%% resume. They used to sit in one table for the whole VM, looked up by
%%% identity alone, so a ticket from one listener authenticated a client
%%% to any other listener in the same VM, including one that only admits
%%% clients holding its external PSK. A ticket now resumes only on the
%%% listener that issued it, for the server name, ALPN and hash it was
%%% issued under, and only once.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_ticket_scope_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("quic.hrl").

-export([all/0, suite/0, init_per_suite/1, end_per_suite/1]).
-export([
    ticket_resumes_where_it_was_issued/1,
    ticket_from_another_listener_is_refused/1,
    ticket_for_another_server_name_is_not_resumed/1,
    ticket_for_another_alpn_is_not_resumed/1,
    ticket_resumes_once/1
]).

-define(SNI, <<"public.example">>).
-define(WAIT_MS, 5000).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [
        ticket_resumes_where_it_was_issued,
        ticket_from_another_listener_is_refused,
        ticket_for_another_server_name_is_not_resumed,
        ticket_for_another_alpn_is_not_resumed,
        ticket_resumes_once
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(quic),
    Config.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Cases
%%====================================================================

%% The control: the issuing listener resumes the session, and accepts
%% early data on it.
ticket_resumes_where_it_was_issued(_Config) ->
    with_public(fun(Port) ->
        Ticket = ticket(Port),
        ?assertEqual(resumed, connect(Port, #{session_ticket => Ticket}))
    end).

%% The reported attack: a ticket from a public listener presented to an
%% unrelated listener that admits only holders of its external PSK.
ticket_from_another_listener_is_refused(_Config) ->
    with_public(fun(Port) ->
        Ticket = ticket(Port),
        {ok, Victim} = quic_test_echo_server:start(#{
            cert => undefined,
            key => undefined,
            alpn => [<<"echo">>],
            psks => #{<<"victim-id">> => <<"this-is-a-32-byte-test-secret!!!">>}
        }),
        try
            ?assertMatch(
                {error, _},
                connect(maps:get(port, Victim), #{session_ticket => Ticket})
            )
        after
            quic_test_echo_server:stop(Victim)
        end
    end).

ticket_for_another_server_name_is_not_resumed(_Config) ->
    with_public(fun(Port) ->
        Ticket = ticket(Port),
        ?assertEqual(
            full_handshake,
            connect(Port, #{session_ticket => Ticket, server_name => <<"other.example">>})
        )
    end).

ticket_for_another_alpn_is_not_resumed(_Config) ->
    with_public(fun(Port) ->
        Ticket = ticket(Port),
        ?assertEqual(
            full_handshake,
            connect(Port, #{session_ticket => Ticket, alpn => [<<"hq-interop">>]})
        )
    end).

ticket_resumes_once(_Config) ->
    with_public(fun(Port) ->
        Ticket = ticket(Port),
        ?assertEqual(resumed, connect(Port, #{session_ticket => Ticket})),
        ?assertEqual(full_handshake, connect(Port, #{session_ticket => Ticket}))
    end).

%%====================================================================
%% Helpers
%%====================================================================

with_public(F) ->
    {ok, Server} = quic_test_echo_server:start(),
    try
        F(maps:get(port, Server))
    after
        quic_test_echo_server:stop(Server)
    end.

%% A ticket from a full handshake with the listener on Port.
ticket(Port) ->
    {ok, Conn} = quic:connect(<<"127.0.0.1">>, Port, client_opts(#{}), self()),
    receive
        {quic, Conn, {session_ticket, Ticket}} ->
            quic:close(Conn, normal),
            Ticket
    after ?WAIT_MS ->
        ct:fail(no_session_ticket)
    end.

%% How a connection offering a ticket came up: resumed when the server
%% took the ticket (it accepts the early data the ticket allows), a full
%% handshake when it did not, an error when it could not come up at all.
connect(Port, Extra) ->
    case quic:connect(<<"127.0.0.1">>, Port, client_opts(Extra), self()) of
        {ok, Conn} ->
            receive
                {quic, Conn, {connected, _Info}} ->
                    Outcome =
                        case quic:early_data_accepted(Conn) of
                            true -> resumed;
                            false -> full_handshake
                        end,
                    quic:close(Conn, normal),
                    Outcome;
                {quic, Conn, {closed, Reason}} ->
                    {error, Reason};
                {quic, Conn, {error, Reason}} ->
                    {error, Reason}
            after ?WAIT_MS ->
                quic:safe_close(Conn, timeout),
                {error, timeout}
            end;
        {error, _} = Error ->
            Error
    end.

client_opts(Extra) ->
    maps:merge(#{verify => false, alpn => [<<"echo">>], server_name => ?SNI}, Extra).
