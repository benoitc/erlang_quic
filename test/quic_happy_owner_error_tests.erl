%%% -*- erlang -*-
%%%
%%% A winning attempt that is already closing when the coordinator hands
%%% it over makes set_owner_sync/2 return {error, {invalid_state, _}}.
%%% The coordinator treats that as a failed attempt instead of crashing
%%% on a try_clause (#399).

-module(quic_happy_owner_error_tests).

-include_lib("eunit/include/eunit.hrl").

closing_winner_test() ->
    Attempt = spawn(fun closing_connection/0),
    ok = meck:new(quic_conn_sup, [passthrough]),
    ok = meck:expect(quic_conn_sup, start_child, fun(_, _, _, Coord) ->
        Coord ! {quic, Attempt, {connected, #{}}},
        {ok, Attempt}
    end),
    try
        ?assertEqual({error, {invalid_state, draining}}, race())
    after
        Attempt ! stop,
        meck:unload(quic_conn_sup)
    end.

%% Answers the coordinator's set_owner_sync/2 as a draining connection does.
closing_connection() ->
    receive
        {'$gen_call', From, _} ->
            gen_statem:reply(From, {error, {invalid_state, draining}}),
            closing_connection();
        stop ->
            ok
    end.

%% The coordinator links to its caller, so run it from a process of its
%% own and report what became of it.
race() ->
    Test = self(),
    {Caller, MRef} = spawn_monitor(fun() ->
        {ok, Coord} = quic_happy:start_coordinator(#{
            addrs => [{{127, 0, 0, 1}, inet}],
            port => 4433,
            opts => #{},
            owner => self(),
            caller => self(),
            delay => 250,
            timeout => 2000
        }),
        receive
            {quic_happy_result, Coord, Result} -> Test ! {result, self(), Result}
        end
    end),
    receive
        {result, Caller, Result} -> Result;
        {'DOWN', MRef, process, Caller, Reason} -> {crashed, Reason}
    after 3000 -> no_result
    end.
